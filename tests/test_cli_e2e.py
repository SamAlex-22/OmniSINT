"""End-to-end integration tests for Task 10: CLI, TUI Dashboard, Custody Verification & Reporting."""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from omnisint.cli import (
    OmniSINTTUIDashboard,
    build_demo_collision_case,
    run_cli,
)
from omnisint.core.storage import CaseStorage


class TestCLIEndToEnd(unittest.TestCase):
    """End-to-end CLI and interactive TUI integration tests."""

    def test_demo_case_separates_colliding_personas_and_exports_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "omnisint_e2e.db"
            md_path = Path(tmpdir) / "dossier.md"
            stix_path = Path(tmpdir) / "bundle.stix.json"

            # 1. Run `omnisint demo` persisting to SQLite + exporting Markdown & STIX 2.1
            code, out = run_cli(
                [
                    "demo",
                    "--db",
                    str(db_path),
                    "--output-md",
                    str(md_path),
                    "--output-stix",
                    str(stix_path),
                ]
            )
            self.assertEqual(code, 0, out)
            self.assertIn("demo-collision-case", out)
            self.assertIn("Resolved Persona Clusters: 4", out)
            self.assertIn("Citation Audit Valid: True", out)
            self.assertTrue(md_path.exists())
            self.assertTrue(stix_path.exists())

            md_text = md_path.read_text(encoding="utf-8")
            self.assertIn("VERIFIED (INTACT)", md_text)
            self.assertIn("alexsec.in", md_text)

            stix_bundle = json.loads(stix_path.read_text(encoding="utf-8"))
            self.assertEqual(stix_bundle["type"], "bundle")

            # 2. `omnisint case list`
            list_code, list_out = run_cli(["case", "list", "--db", str(db_path)])
            self.assertEqual(list_code, 0, list_out)
            self.assertIn("demo-collision-case", list_out)

            # 3. `omnisint case verify` passes on untampered database
            verify_code, verify_out = run_cli(["case", "verify", "demo-collision-case", "--db", str(db_path)])
            self.assertEqual(verify_code, 0, verify_out)
            self.assertIn("Custody VERIFIED (INTACT)", verify_out)

            # 4. `omnisint case show` & `omnisint report`
            show_code, show_out = run_cli(["case", "show", "demo-collision-case", "--db", str(db_path)])
            self.assertEqual(show_code, 0, show_out)
            self.assertIn("Identity Confidence Matrix", show_out)

            rep_code, rep_out = run_cli(
                ["report", "demo-collision-case", "--format", "stix", "--db", str(db_path)]
            )
            self.assertEqual(rep_code, 0, rep_out)
            self.assertEqual(json.loads(rep_out)["type"], "bundle")

            # 5. `omnisint tui --snapshot`
            tui_code, tui_out = run_cli(
                ["tui", "demo-collision-case", "--db", str(db_path), "--snapshot"]
            )
            self.assertEqual(tui_code, 0, tui_out)
            self.assertIn("INFORMATION HIERARCHY TREE", tui_out)

            # 6. Tamper detection via SQLite -> `case verify` must exit non-zero!
            async def _tamper_db() -> None:
                async with CaseStorage(db_path) as store:
                    conn = await store._ensure_conn()
                    with conn:
                        conn.execute(
                            "UPDATE evidence_items SET raw_payload_json = '{\"tampered\":true}' WHERE seq_index = 0;"
                        )

            asyncio.run(_tamper_db())
            tamper_code, tamper_out = run_cli(["case", "verify", "demo-collision-case", "--db", str(db_path)])
            self.assertNotEqual(tamper_code, 0)
            self.assertIn("Custody FAILED", tamper_out)

    def test_tui_dashboard_interactive_views_and_persona_navigation(self) -> None:
        case, _ = build_demo_collision_case()
        dashboard = OmniSINTTUIDashboard(case)

        self.assertGreaterEqual(len(case.personas), 4)
        hierarchy_view = dashboard.render_screen()
        self.assertIn("INFORMATION HIERARCHY TREE", hierarchy_view)
        self.assertIn("VERIFIED (INTACT)", hierarchy_view)

        dashboard.next_persona()
        self.assertEqual(dashboard.selected_persona_index, 1)
        dashboard.prev_persona()
        self.assertEqual(dashboard.selected_persona_index, 0)

        dashboard.set_view_mode("matrix")
        self.assertIn("IDENTITY CONFIDENCE MATRIX", dashboard.render_screen())

        dashboard.set_view_mode("custody")
        self.assertIn("SHA-256 CHAIN OF CUSTODY LEDGER", dashboard.render_screen())

        dashboard.set_view_mode("brief")
        self.assertIn("CITATION-LOCKED AI EXECUTIVE BRIEF", dashboard.render_screen())


if __name__ == "__main__":
    unittest.main()
