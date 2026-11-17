"""SHA-256 chain-of-custody ledger for OmniSINT evidence.

Every collected artifact becomes an `EvidenceItem` whose payload digest (`sha256_hash`) is
chained to the previous item's `chain_hash`. The chain is *tamper-evident* against edits that
do not recompute the chain. Anyone with write access to the store can rebuild a consistent
chain, so for third-party verifiability the chain head must be signed or anchored externally
(see `omnisint.core.signing`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any, Literal

from omnisint.core.models import AuditLogEntry, EvidenceItem, new_uuid, utc_now

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    HAS_ED25519 = True
except ImportError:  # pragma: no cover
    Ed25519PrivateKey = None  # type: ignore[assignment,misc]
    Ed25519PublicKey = None  # type: ignore[assignment,misc]
    serialization = None  # type: ignore[assignment]
    HAS_ED25519 = False

GENESIS_CHAIN_HASH = "0" * 64
CHAIN_HASH_VERSION = "omnisint-custody-v2"

PayloadKind = Literal["json", "text", "bytes"]
RawPayload = str | bytes | dict[str, Any] | list[Any]


def payload_kind(payload: RawPayload) -> PayloadKind:
    """Return the structural kind of a raw payload ("json", "text", or "bytes")."""
    if isinstance(payload, bytes):
        return "bytes"
    if isinstance(payload, str):
        return "text"
    return "json"


def canonicalize_payload(payload: RawPayload) -> bytes:
    """Serialize a raw OSINT payload into deterministic canonical bytes.

    - `bytes` are hashed as-is (so the digest matches `sha256sum` of the original file).
    - `str` is encoded as UTF-8 (matches `sha256sum` of the original response body).
    - `dict` / `list` are serialized as canonical JSON with sorted keys and no whitespace.
    """
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        return payload.encode("utf-8")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def compute_sha256(payload: RawPayload) -> str:
    """Compute hex-encoded SHA-256 digest of a canonicalized payload."""
    return hashlib.sha256(canonicalize_payload(payload)).hexdigest()


def compute_chain_hash(
    prev_chain_hash: str,
    payload_sha256: str,
    collector_name: str,
    source_uri: str,
    collected_at_iso: str,
    *,
    evidence_id: str,
    case_id: str,
    mime_type: str = "application/json",
    kind: PayloadKind = "json",
) -> str:
    """Compute the tamper-evident chained SHA-256 digest for one evidence record.

    The hashed material is a canonical JSON object (not a delimiter-joined string), so field
    boundaries are unambiguous even if a URI contains separator characters. `evidence_id` and
    `case_id` are bound into the hash so citations cannot be silently re-pointed, and the
    payload `kind` separates a raw text body from a structurally identical JSON object.
    """
    material = {
        "v": CHAIN_HASH_VERSION,
        "prev_chain_hash": prev_chain_hash,
        "evidence_id": evidence_id,
        "case_id": case_id,
        "payload_sha256": payload_sha256,
        "payload_kind": kind,
        "mime_type": mime_type,
        "collector_name": collector_name,
        "source_uri": source_uri,
        "collected_at_utc": collected_at_iso,
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def compute_item_chain_hash(item: EvidenceItem, prev_chain_hash: str | None = None) -> str:
    """Recompute the chain hash for an EvidenceItem (optionally against a different predecessor)."""
    return compute_chain_hash(
        prev_chain_hash=item.prev_chain_hash if prev_chain_hash is None else prev_chain_hash,
        payload_sha256=item.sha256_hash,
        collector_name=item.collector_name,
        source_uri=item.source_uri,
        collected_at_iso=item.collected_at_utc.isoformat(),
        evidence_id=item.evidence_id,
        case_id=item.case_id,
        mime_type=item.mime_type,
        kind=payload_kind(item.raw_payload),
    )


class CustodyLedger:
    """Manages evidence acquisition, hash chaining, and the audit trail for a Case."""

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
        raw_payload: str | dict[str, Any] | list[Any],
        mime_type: str = "application/json",
        notes: str = "",
        actor: str = "omnisint-collector",
    ) -> EvidenceItem:
        """Hash a raw OSINT response, append it to the tamper-evident chain, and log acquisition."""
        timestamp = utc_now()
        evidence_id = new_uuid()
        payload_hash = compute_sha256(raw_payload)
        prev_hash = self.head_chain_hash
        chained_hash = compute_chain_hash(
            prev_chain_hash=prev_hash,
            payload_sha256=payload_hash,
            collector_name=collector_name,
            source_uri=source_uri,
            collected_at_iso=timestamp.isoformat(),
            evidence_id=evidence_id,
            case_id=self.case_id,
            mime_type=mime_type,
            kind=payload_kind(raw_payload),
        )

        item = EvidenceItem(
            evidence_id=evidence_id,
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
        """Verify that an EvidenceItem's payload digest and chain hash are internally consistent."""
        if compute_sha256(item.raw_payload) != item.sha256_hash:
            return False
        return compute_item_chain_hash(item) == item.chain_hash

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Verify every payload digest, chain link, and case binding across the ledger."""
        violations: list[str] = []
        expected_prev = GENESIS_CHAIN_HASH

        for idx, item in enumerate(self._evidence):
            if item.case_id != self.case_id:
                violations.append(
                    f"Case binding mismatch at index {idx} (evidence_id={item.evidence_id}): "
                    f"expected case_id={self.case_id}, got {item.case_id}"
                )
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


class CustodySigner:
    """Signs and verifies a CustodyLedger head state using Ed25519 (or HMAC-SHA256 fallback)."""

    def __init__(self, private_key_hex: str | None = None) -> None:
        if HAS_ED25519:
            assert Ed25519PrivateKey is not None
            assert serialization is not None
            if private_key_hex is not None:
                raw_seed = bytes.fromhex(private_key_hex)
                self._priv = Ed25519PrivateKey.from_private_bytes(raw_seed)
            else:
                self._priv = Ed25519PrivateKey.generate()
            self._pub = self._priv.public_key()
            self._hmac_key: bytes | None = None
        else:  # pragma: no cover
            self._priv = None
            self._pub = None
            self._hmac_key = (
                bytes.fromhex(private_key_hex)
                if private_key_hex is not None
                else secrets.token_bytes(32)
            )

    @property
    def algorithm(self) -> str:
        """Return active signing algorithm identifier."""
        return "Ed25519" if HAS_ED25519 else "HMAC-SHA256"

    @property
    def private_key_hex(self) -> str:
        """Return hex-encoded 32-byte private key seed."""
        if HAS_ED25519 and self._priv is not None and serialization is not None:
            raw = self._priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            return raw.hex()
        assert self._hmac_key is not None  # pragma: no cover
        return self._hmac_key.hex()  # pragma: no cover

    @property
    def public_key_hex(self) -> str:
        """Return hex-encoded public verification key (or HMAC key digest in fallback mode)."""
        if HAS_ED25519 and self._pub is not None and serialization is not None:
            raw = self._pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return raw.hex()
        assert self._hmac_key is not None  # pragma: no cover
        return self._hmac_key.hex()  # pragma: no cover

    @staticmethod
    def _ledger_message(ledger: CustodyLedger) -> bytes:
        """Serialize canonical ledger head state into deterministic UTF-8 bytes."""
        payload = {
            "v": CHAIN_HASH_VERSION,
            "case_id": ledger.case_id,
            "head_chain_hash": ledger.head_chain_hash,
            "item_count": len(ledger.evidence_items),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign_ledger(self, ledger: CustodyLedger) -> str:
        """Sign the CustodyLedger head state and return a hex-encoded signature."""
        msg = self._ledger_message(ledger)
        if HAS_ED25519 and self._priv is not None:
            return self._priv.sign(msg).hex()
        assert self._hmac_key is not None  # pragma: no cover
        return hmac.new(self._hmac_key, msg, hashlib.sha256).hexdigest()  # pragma: no cover

    @classmethod
    def verify_signature(
        cls,
        ledger: CustodyLedger,
        signature_hex: str,
        public_key_hex: str,
    ) -> bool:
        """Verify a hex signature against a CustodyLedger head state and hex public key."""
        msg = cls._ledger_message(ledger)
        try:
            sig_bytes = bytes.fromhex(signature_hex)
            key_bytes = bytes.fromhex(public_key_hex)
        except ValueError:
            return False

        if HAS_ED25519:
            assert Ed25519PublicKey is not None
            try:
                pub = Ed25519PublicKey.from_public_bytes(key_bytes)
                pub.verify(sig_bytes, msg)
                return True
            except Exception:
                return False

        expected = hmac.new(key_bytes, msg, hashlib.sha256).digest()  # pragma: no cover
        return hmac.compare_digest(expected, sig_bytes)  # pragma: no cover

