"""Textual interactive terminal dashboard (with deterministic headless snapshot fallback) for OmniSINT."""

from __future__ import annotations

from typing import Literal

from omnisint.core.custody import CustodyLedger
from omnisint.core.models import Case, EntityNode, PersonaCluster
from omnisint.intelligence.ai_analyst import AIAnalyst
from omnisint.intelligence.graph_engine import render_hierarchy_ascii

try:
    from textual.app import App, ComposeResult  # type: ignore[import-untyped]
    from textual.widgets import Footer, Header, Static  # type: ignore[import-untyped]

    HAS_TEXTUAL = True
except ImportError:  # pragma: no cover
    App = object  # type: ignore[assignment,misc]
    ComposeResult = Any = object  # type: ignore[assignment,misc]
    Footer = Header = Static = None
    HAS_TEXTUAL = False

TUIViewMode = Literal["hierarchy", "matrix", "custody", "brief"]


class OmniSINTTUIDashboard:
    """Stateful interactive terminal dashboard controller for OmniSINT Cases."""

    def __init__(self, case: Case) -> None:
        self.case = case
        self.selected_persona_index: int = 0
        self.selected_node_id: str | None = (
            case.nodes[0].node_id if case.nodes else None
        )
        self.view_mode: TUIViewMode = "hierarchy"
        self._ledger = CustodyLedger(
            case_id=case.case_id,
            existing_evidence=case.evidence_ledger,
            existing_audit_log=case.audit_log,
        )

    @property
    def active_persona(self) -> PersonaCluster | None:
        """Return currently selected PersonaCluster or None."""
        if not self.case.personas:
            return None
        idx = max(0, min(self.selected_persona_index, len(self.case.personas) - 1))
        return self.case.personas[idx]

    @property
    def active_node(self) -> EntityNode | None:
        """Return currently selected EntityNode or None."""
        if not self.case.nodes:
            return None
        if self.selected_node_id:
            for node in self.case.nodes:
                if node.node_id == self.selected_node_id:
                    return node
        return self.case.nodes[0]

    def select_persona(self, index: int) -> PersonaCluster | None:
        """Select a PersonaCluster by zero-based index."""
        if not self.case.personas:
            self.selected_persona_index = 0
            return None
        self.selected_persona_index = max(0, min(index, len(self.case.personas) - 1))
        persona = self.active_persona
        if persona and persona.node_ids:
            self.selected_node_id = persona.node_ids[0]
        return persona

    def next_persona(self) -> PersonaCluster | None:
        """Cycle to the next PersonaCluster."""
        if not self.case.personas:
            return None
        return self.select_persona((self.selected_persona_index + 1) % len(self.case.personas))

    def prev_persona(self) -> PersonaCluster | None:
        """Cycle to the previous PersonaCluster."""
        if not self.case.personas:
            return None
        return self.select_persona((self.selected_persona_index - 1) % len(self.case.personas))

    def select_node(self, node_id: str) -> EntityNode | None:
        """Select an EntityNode by ID."""
        for node in self.case.nodes:
            if node.node_id == node_id:
                self.selected_node_id = node_id
                return node
        return None

    def set_view_mode(self, mode: TUIViewMode) -> None:
        """Switch right-pane inspection view (`hierarchy`, `matrix`, `custody`, `brief`)."""
        self.view_mode = mode

    def render_screen(self, width: int = 100) -> str:
        """Render the multi-panel OmniSINT terminal dashboard as a formatted string."""
        bar = "=" * max(40, width)
        sub_bar = "-" * max(40, width)
        custody_ok, violations = self._ledger.verify_chain()
        custody_status = "VERIFIED (INTACT)" if custody_ok else f"FAILED ({len(violations)} issues)"

        lines: list[str] = [
            bar,
            f" OmniSINT TUI // Case: {self.case.title} [{self.case.case_id}]",
            f" Query: {self.case.target_query} | Status: {self.case.status.value} | "
            f"Nodes: {len(self.case.nodes)} | Personas: {len(self.case.personas)} | "
            f"Custody: {custody_status}",
            f" Active View: [{self.view_mode.upper()}]  Keys: [1]Hierarchy [2]Matrix [3]Custody [4]Brief [N/P]Persona",
            bar,
        ]

        # Persona Tabs
        if self.case.personas:
            tabs = []
            for idx, p in enumerate(self.case.personas):
                marker = "*" if idx == self.selected_persona_index else " "
                tabs.append(f"[{marker}#{idx + 1} {p.primary_handle} ({p.inferred_timezone or 'TZ?'})]")
            lines.append(" Personas: " + "  ".join(tabs))
        else:
            lines.append(" Personas: (none resolved yet)")
        lines.append(sub_bar)

        if self.view_mode == "hierarchy":
            persona = self.active_persona
            if persona and persona.hierarchy_tree is not None:
                lines.append(" [INFORMATION HIERARCHY TREE]")
                lines.append(render_hierarchy_ascii(persona.hierarchy_tree))
            else:
                lines.append(" [INFORMATION HIERARCHY TREE] No hierarchy tree available.")
            lines.append(sub_bar)
            node = self.active_node
            if node is not None:
                lines.append(
                    f" [SELECTED NODE] {node.label} (id={node.node_id}, type={node.entity_type.value})"
                )
                lines.append(
                    f" Entropy={node.entropy_score:.2f} bits | Rarity={node.rarity_score:.2f} | "
                    f"Confidence={node.confidence:.2f} | Evidence={len(node.evidence_ids)}"
                )

        elif self.view_mode == "matrix":
            lines.append(" [IDENTITY CONFIDENCE MATRIX]")
            analyst = AIAnalyst(provider="deterministic")
            matrix = analyst.build_identity_matrix(self.case)
            for row in matrix:
                lines.append(
                    f" • {row.persona_label} | Tier={row.confidence_tier} ({row.confidence_score:.2f}) | "
                    f"H={row.avg_handle_entropy:.2f} | TZ={row.inferred_timezone or 'N/A'}"
                )
                lines.append(f"   Modalities: {', '.join(row.corroborating_modalities)}")

        elif self.view_mode == "custody":
            lines.append(f" [SHA-256 CHAIN OF CUSTODY LEDGER] Integrity={custody_status}")
            lines.append(f" Head Chain Hash: {self._ledger.head_chain_hash}")
            for idx, ev in enumerate(self.case.evidence_ledger, start=1):
                lines.append(
                    f" {idx:02d}. {ev.evidence_id[:12]}.. | {ev.collector_name:<20} | "
                    f"sha256={ev.sha256_hash[:16]}.. | {ev.source_uri}"
                )

        elif self.view_mode == "brief":
            lines.append(" [CITATION-LOCKED AI EXECUTIVE BRIEF]")
            lines.append(self.case.ai_executive_brief or "No executive brief generated yet.")

        lines.append(bar)
        return "\n".join(lines)


if HAS_TEXTUAL:  # pragma: no cover

    class _OmniSINTTextualApp(App):  # type: ignore[misc]
        """Textual interactive TUI wrapper around OmniSINTTUIDashboard."""

        BINDINGS = [
            ("1", "set_view('hierarchy')", "Hierarchy"),
            ("2", "set_view('matrix')", "Matrix"),
            ("3", "set_view('custody')", "Custody"),
            ("4", "set_view('brief')", "Brief"),
            ("n", "next_persona", "Next Persona"),
            ("p", "prev_persona", "Prev Persona"),
            ("q", "quit", "Quit"),
        ]

        def __init__(self, dashboard: OmniSINTTUIDashboard) -> None:
            super().__init__()
            self.dashboard = dashboard

        def compose(self) -> ComposeResult:
            yield Header()
            yield Static(self.dashboard.render_screen(), id="omnisint-panel")
            yield Footer()

        def _refresh_view(self) -> None:
            panel = self.query_one("#omnisint-panel", Static)
            panel.update(self.dashboard.render_screen())

        def action_set_view(self, mode: TUIViewMode) -> None:
            self.dashboard.set_view_mode(mode)
            self._refresh_view()

        def action_next_persona(self) -> None:
            self.dashboard.next_persona()
            self._refresh_view()

        def action_prev_persona(self) -> None:
            self.dashboard.prev_persona()
            self._refresh_view()


def launch_tui(case: Case, interactive: bool = True) -> str:
    """Launch the Textual TUI when available & interactive, or return rendered dashboard text."""
    dashboard = OmniSINTTUIDashboard(case)
    if HAS_TEXTUAL and interactive:  # pragma: no cover
        _OmniSINTTextualApp(dashboard).run()
    return dashboard.render_screen()
