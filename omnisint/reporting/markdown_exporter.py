"""Investigative Markdown dossier exporter with Hierarchy Trees & SHA-256 Chain of Custody tables."""

from __future__ import annotations

from omnisint.core.custody import CustodyLedger, CustodySigner
from omnisint.core.models import Case, HierarchyTreeNode
from omnisint.intelligence.graph_engine import render_hierarchy_ascii


def _hierarchy_tree_to_mermaid(tree: HierarchyTreeNode) -> str:
    """Convert a PersonaCluster HierarchyTreeNode into a Mermaid flowchart TD diagram."""
    lines: list[str] = ["flowchart TD"]
    seen_edges: set[tuple[str, str]] = set()

    def _safe_id(raw: str) -> str:
        cleaned = "".join(ch if ch.isalnum() else "_" for ch in raw)
        return f"n_{cleaned}"

    def _safe_label(text: str) -> str:
        return text.replace('"', "'").replace("\n", " ")[:70]

    def _walk(node: HierarchyTreeNode) -> None:
        nid = _safe_id(node.node_id)
        lines.append(f'    {nid}["{_safe_label(node.label)}"]')
        for child in node.children:
            cid = _safe_id(child.node_id)
            edge = (nid, cid)
            if edge not in seen_edges:
                seen_edges.add(edge)
                lines.append(f"    {nid} --> {cid}")
            _walk(child)

    _walk(tree)
    return "\n".join(lines)


class MarkdownExporter:
    """Exports an OmniSINT Case into a complete, evidentiary Markdown investigative dossier."""

    def export(
        self,
        case: Case,
        verify_custody: bool = True,
        signer: CustodySigner | None = None,
    ) -> str:
        """Render a Case into a structured Markdown investigative dossier."""
        ledger = CustodyLedger(
            case_id=case.case_id,
            existing_evidence=case.evidence_ledger,
            existing_audit_log=case.audit_log,
        )
        custody_valid, violations = ledger.verify_chain() if verify_custody else (True, [])
        custody_badge = "VERIFIED (INTACT)" if custody_valid else f"FAILED ({len(violations)} violations)"

        sections: list[str] = [
            f"# OmniSINT Investigative Dossier: {case.title}",
            "",
            "## Case Metadata",
            f"- **Case ID:** `{case.case_id}`",
            f"- **Target Query:** `{case.target_query}`",
            f"- **Investigator:** `{case.investigator}`",
            f"- **Status:** `{case.status.value}`",
            f"- **Created (UTC):** `{case.created_at_utc.isoformat()}`",
            f"- **Updated (UTC):** `{case.updated_at_utc.isoformat()}`",
            f"- **Custody Chain Integrity:** **{custody_badge}** (`head_chain_hash={ledger.head_chain_hash}`)",
        ]

        if signer is not None:
            sig = signer.sign_ledger(ledger)
            sections.append(
                f"- **Ledger Head Signature ({signer.algorithm}):** `{sig}` (pubkey: `{signer.public_key_hex}`)"
            )

        if violations:
            sections.extend(["", "### Custody Integrity Violations"])
            for v in violations:
                sections.append(f"- `{v}`")

        # Executive Brief (if already synthesized by AIAnalyst)
        if case.ai_executive_brief.strip():
            sections.extend(["", "---", "", case.ai_executive_brief.strip()])

        # Persona Clusters & Visual Hierarchy Trees
        sections.extend(["", "---", "", f"## Resolved Persona Clusters ({len(case.personas)})"])
        if not case.personas:
            sections.append("_No persona clusters resolved yet._")
        for persona in case.personas:
            sections.extend(
                [
                    "",
                    f"### {persona.persona_label} (`{persona.cluster_id}`)",
                    f"- **Primary Handle:** `{persona.primary_handle}`",
                    f"- **Confidence Score:** `{persona.confidence_score:.2f}`",
                    f"- **Avg Handle Entropy:** `{persona.avg_handle_entropy:.2f}` bits",
                    f"- **Inferred Timezone:** `{persona.inferred_timezone or 'Unknown'}`",
                    f"- **Entities (`{len(persona.node_ids)}`):** "
                    + (", ".join(f"`{nid}`" for nid in persona.node_ids) or "None"),
                ]
            )
            if persona.hierarchy_tree is not None:
                sections.extend(
                    [
                        "",
                        "#### ASCII Information Hierarchy Tree",
                        "```text",
                        render_hierarchy_ascii(persona.hierarchy_tree),
                        "```",
                        "",
                        "#### Mermaid Hierarchy Graph",
                        "```mermaid",
                        _hierarchy_tree_to_mermaid(persona.hierarchy_tree),
                        "```",
                    ]
                )

        # SHA-256 Chain of Custody Evidence Ledger Table
        sections.extend(
            [
                "",
                "---",
                "",
                f"## SHA-256 Chain of Custody Evidence Ledger ({len(case.evidence_ledger)} items)",
                "| # | Evidence ID | Collector | Source URI | Payload SHA-256 | Chain Hash | Collected UTC |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for idx, ev in enumerate(case.evidence_ledger, start=1):
            sections.append(
                f"| {idx} | `{ev.evidence_id}` | `{ev.collector_name}` | `{ev.source_uri}` | "
                f"`{ev.sha256_hash[:16]}...` | `{ev.chain_hash[:16]}...` | `{ev.collected_at_utc.isoformat()}` |"
            )

        # Audit Trail
        sections.extend(
            [
                "",
                f"## Investigative Audit Log ({len(case.audit_log)} entries)",
                "| Timestamp UTC | Actor | Action | Evidence ID |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for entry in case.audit_log:
            ev_col = f"`{entry.evidence_id}`" if entry.evidence_id else "-"
            sections.append(
                f"| `{entry.timestamp_utc.isoformat()}` | `{entry.actor}` | `{entry.action}` | {ev_col} |"
            )

        return "\n".join(sections).strip() + "\n"
