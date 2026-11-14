"""OSINT Pilot-grade Chain of Custody & SHA-256 Evidentiary Ledger for OmniSINT."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from omnisint.core.models import AuditLogEntry, EvidenceItem, utc_now

GENESIS_CHAIN_HASH = "0" * 64


def canonicalize_payload(payload: str | bytes | dict[str, Any] | list[Any]) -> bytes:
    """Serialize any raw OSINT payload into deterministic canonical UTF-8 bytes."""
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        return payload.encode("utf-8")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def compute_sha256(payload: str | bytes | dict[str, Any] | list[Any]) -> str:
    """Compute hex-encoded SHA-256 digest of a canonicalized payload."""
    return hashlib.sha256(canonicalize_payload(payload)).hexdigest()


def compute_chain_hash(
    prev_chain_hash: str,
    payload_sha256: str,
    collector_name: str,
    source_uri: str,
    collected_at_iso: str,
) -> str:
    """Compute tamper-evident chained SHA-256 digest linking previous evidence record."""
    material = f"{prev_chain_hash}|{payload_sha256}|{collector_name}|{source_uri}|{collected_at_iso}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class CustodyLedger:
    """Manages cryptographic evidence acquisition, hash chaining, and audit trail for a Case."""

    def __init__(
        self,
        case_id: str,
        existing_evidence: list[EvidenceItem] | None = None,
        existing_audit_log: list[AuditLogEntry] | None = None,
    ) -> None:
        self.case_id = case_id
        self._evidence: list[EvidenceItem] = list(existing_evidence or [])
        self._audit_log: list[AuditLogEntry] = list(existing_audit_log or [])

    @property
    def evidence_items(self) -> list[EvidenceItem]:
        """Return copy of recorded evidence items."""
        return list(self._evidence)

    @property
    def audit_log(self) -> list[AuditLogEntry]:
        """Return copy of recorded audit log entries."""
        return list(self._audit_log)

    @property
    def head_chain_hash(self) -> str:
        """Return the latest chain hash in the ledger, or GENESIS_CHAIN_HASH if empty."""
        if not self._evidence:
            return GENESIS_CHAIN_HASH
        return self._evidence[-1].chain_hash

    def record_evidence(
        self,
        collector_name: str,
        source_uri: str,
        raw_payload: str | dict[str, Any],
        mime_type: str = "application/json",
        notes: str = "",
        actor: str = "omnisint-collector",
    ) -> EvidenceItem:
        """Hash a raw OSINT response, append it to the tamper-evident chain, and log acquisition."""
        timestamp = utc_now()
        payload_hash = compute_sha256(raw_payload)
        prev_hash = self.head_chain_hash
        chained_hash = compute_chain_hash(
            prev_chain_hash=prev_hash,
            payload_sha256=payload_hash,
            collector_name=collector_name,
            source_uri=source_uri,
            collected_at_iso=timestamp.isoformat(),
        )

        item = EvidenceItem(
            case_id=self.case_id,
            collector_name=collector_name,
            source_uri=source_uri,
            sha256_hash=payload_hash,
            prev_chain_hash=prev_hash,
            chain_hash=chained_hash,
            collected_at_utc=timestamp,
            raw_payload=raw_payload,
            mime_type=mime_type,
            notes=notes,
        )
        self._evidence.append(item)

        self.log_action(
            action="EVIDENCE_ACQUIRED",
            actor=actor,
            evidence_id=item.evidence_id,
            details={
                "collector_name": collector_name,
                "source_uri": source_uri,
                "sha256_hash": payload_hash,
                "chain_hash": chained_hash,
            },
        )
        return item

    def log_action(
        self,
        action: str,
        actor: str = "omnisint-system",
        evidence_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        """Append an investigative or system event to the Case audit log."""
        entry = AuditLogEntry(
            case_id=self.case_id,
            actor=actor,
            action=action,
            evidence_id=evidence_id,
            details=details or {},
        )
        self._audit_log.append(entry)
        return entry

    @staticmethod
    def verify_item(item: EvidenceItem) -> bool:
        """Verify that an EvidenceItem's raw payload matches its recorded SHA-256 digest."""
        expected_payload_hash = compute_sha256(item.raw_payload)
        if expected_payload_hash != item.sha256_hash:
            return False

        expected_chain_hash = compute_chain_hash(
            prev_chain_hash=item.prev_chain_hash,
            payload_sha256=item.sha256_hash,
            collector_name=item.collector_name,
            source_uri=item.source_uri,
            collected_at_iso=item.collected_at_utc.isoformat(),
        )
        return expected_chain_hash == item.chain_hash

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Verify the entire cryptographic chain of custody across all recorded evidence items."""
        violations: list[str] = []
        expected_prev = GENESIS_CHAIN_HASH

        for idx, item in enumerate(self._evidence):
            if item.prev_chain_hash != expected_prev:
                violations.append(
                    f"Chain break at index {idx} (evidence_id={item.evidence_id}): "
                    f"expected prev_chain_hash={expected_prev}, got {item.prev_chain_hash}"
                )
            if not self.verify_item(item):
                violations.append(
                    f"Payload or chain hash mismatch at index {idx} (evidence_id={item.evidence_id})"
                )
            expected_prev = item.chain_hash

        return (len(violations) == 0, violations)
