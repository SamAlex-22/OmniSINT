"""Command-line interface (`omnisint`) for scans, case custody verification, pivoting, TUI, and reporting."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Sequence

import click

from omnisint.api import create_app
from omnisint.cli.tui import launch_tui
from omnisint.collectors import (
    DEFAULT_PLATFORM_SPECS,
    PlatformSpec,
    ScraplingCollector,
    create_default_registry,
    load_sherlock_specs,
    load_whatsmyname_specs,
)
from omnisint.config import get_settings
from omnisint.core.custody import CustodyLedger
from omnisint.core.models import (
    Case,
    CaseStatus,
    EntityNode,
    EntityType,
    RelationshipEdge,
    RelationType,
)
from omnisint.core.orchestrator import ScanOrchestrator
from omnisint.core.storage import CaseStorage
from omnisint.intelligence.ai_analyst import AIAnalysisReport, AIAnalyst
from omnisint.intelligence.graph_engine import KnowledgeGraphEngine, render_hierarchy_ascii
from omnisint.intelligence.similarity import compute_dhash_from_pixels
from omnisint.reporting import MarkdownExporter, STIXExporter


def build_demo_collision_case() -> tuple[Case, AIAnalysisReport]:
    """Construct and analyze a realistic offline OSINT collision scenario separating distinct personas."""
    ledger = CustodyLedger(case_id="demo-collision-case")
    ev_a1 = ledger.record_evidence(
        collector_name="github_collector",
        source_uri="https://api.github.com/users/alex_dev",
        raw_payload={"login": "alex_dev", "location": "Bengaluru, India", "email": "alex.sec@proton.me"},
    )
    ev_a2 = ledger.record_evidence(
        collector_name="username_collector",
        source_uri="https://x.com/dev_alex_sec",
        raw_payload={"handle": "dev_alex_sec", "location": "Bengaluru, India"},
    )
    ev_a3 = ledger.record_evidence(
        collector_name="domain_ct_collector",
        source_uri="https://crt.sh/?q=alexsec.in&output=json",
        raw_payload=[{"common_name": "api.alexsec.in"}],
    )
    ev_b1 = ledger.record_evidence(
        collector_name="username_collector",
        source_uri="https://gitlab.com/alex_dev",
        raw_payload={"handle": "alex_dev", "location": "Seattle, USA", "email": "alex@seattle-cloud.io"},
    )
    ev_js1 = ledger.record_evidence(
        collector_name="username_collector",
        source_uri="https://github.com/john_smith",
        raw_payload={"login": "john_smith"},
    )
    ev_js2 = ledger.record_evidence(
        collector_name="username_collector",
        source_uri="https://reddit.com/user/john_smith/about.json",
        raw_payload={"name": "john_smith"},
    )

    grid_a = [[(r * 25 + c * 12) % 255 for c in range(9)] for r in range(8)]
    dhash_a = compute_dhash_from_pixels(grid_a)

    nodes = [
        EntityNode(
            node_id="demo-a-gh",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="alex_dev",
            platform="GitHub",
            evidence_ids=[ev_a1.evidence_id],
            attributes={
                "location": "Bengaluru, India",
                "avatar_hash": dhash_a,
                "timestamps": ["2026-05-04T14:15:00+05:30", "2026-05-05T15:30:00+05:30"],
            },
        ),
        EntityNode(
            node_id="demo-a-tw",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="dev_alex_sec",
            platform="Twitter",
            evidence_ids=[ev_a2.evidence_id],
            attributes={
                "location": "Bengaluru, India",
                "avatar_hash": dhash_a,
                "timestamps": ["2026-05-06T14:50:00+05:30", "2026-05-07T16:10:00+05:30"],
            },
        ),
        EntityNode(
            node_id="demo-a-email",
            entity_type=EntityType.EMAIL,
            value="alex.sec@proton.me",
            evidence_ids=[ev_a1.evidence_id],
        ),
        EntityNode(
            node_id="demo-a-domain",
            entity_type=EntityType.DOMAIN,
            value="alexsec.in",
            evidence_ids=[ev_a3.evidence_id],
        ),
        EntityNode(
            node_id="demo-a-sub",
            entity_type=EntityType.SUBDOMAIN,
            value="api.alexsec.in",
            evidence_ids=[ev_a3.evidence_id],
        ),
        EntityNode(
            node_id="demo-b-gl",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="alex_dev",
            platform="GitLab",
            evidence_ids=[ev_b1.evidence_id],
            attributes={
                "location": "Seattle, USA",
                "timestamps": ["2026-05-04T14:10:00-07:00", "2026-05-05T15:20:00-07:00"],
            },
        ),
        EntityNode(
            node_id="demo-js-gh",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="john_smith",
            platform="GitHub",
            evidence_ids=[ev_js1.evidence_id],
        ),
        EntityNode(
            node_id="demo-js-rd",
            entity_type=EntityType.SOCIAL_PROFILE,
            value="john_smith",
            platform="Reddit",
            evidence_ids=[ev_js2.evidence_id],
        ),
    ]

    edges = [
        RelationshipEdge(
            source_node_id="demo-a-gh",
            target_node_id="demo-a-email",
            relation_type=RelationType.HAS_EMAIL,
            evidence_ids=[ev_a1.evidence_id],
        ),
        RelationshipEdge(
            source_node_id="demo-a-gh",
            target_node_id="demo-a-domain",
            relation_type=RelationType.OWNS_DOMAIN,
            evidence_ids=[ev_a3.evidence_id],
        ),
        RelationshipEdge(
            source_node_id="demo-a-domain",
            target_node_id="demo-a-sub",
            relation_type=RelationType.HAS_SUBDOMAIN,
            evidence_ids=[ev_a3.evidence_id],
        ),
    ]

    case = Case(
        case_id="demo-collision-case",
        title="Namesake Disambiguation Demo (alex_dev + john_smith)",
        target_query="alex_dev",
        status=CaseStatus.COMPLETED,
        nodes=nodes,
        edges=edges,
        evidence_ledger=ledger.evidence_items,
        audit_log=ledger.audit_log,
    )
    KnowledgeGraphEngine().apply_to_case(case)
    report = AIAnalyst(provider="deterministic").analyze_case_sync(case, run_graph_disambiguation=False)
    return case, report


def _resolve_db_path(db: str | None) -> str:
    return db or str(get_settings().database_path)


@click.group(help="OmniSINT — Open-Source OSINT Aggregation, Case Custody & Entity-Resolution CLI.")
def app() -> None:
    """OmniSINT top-level CLI group."""


@app.command("demo")
@click.option("--db", default=None, help="Optional SQLite database path to persist the demo case.")
@click.option("--output-md", default=None, help="Optional path to save Markdown dossier.")
@click.option("--output-stix", default=None, help="Optional path to save STIX 2.1 JSON bundle.")
def cmd_demo(db: str | None, output_md: str | None, output_stix: str | None) -> None:
    """Run an offline colliding-namesake disambiguation demonstration."""
    case, report = build_demo_collision_case()
    if db:
        async def _save() -> None:
            async with CaseStorage(db) as store:
                await store.save_case(case)
        asyncio.run(_save())

    click.echo(f"Case ID: {case.case_id}")
    click.echo(f"Resolved Persona Clusters: {len(case.personas)}")
    for persona in case.personas:
        click.echo(f"\n--- {persona.persona_label} (conf={persona.confidence_score:.2f}) ---")
        if persona.hierarchy_tree is not None:
            click.echo(render_hierarchy_ascii(persona.hierarchy_tree))

    click.echo(f"\nCitation Audit Valid: {report.citation_audit.is_valid}")

    if output_md:
        Path(output_md).write_text(MarkdownExporter().export(case), encoding="utf-8")
        click.echo(f"Wrote Markdown dossier -> {output_md}")
    if output_stix:
        Path(output_stix).write_text(STIXExporter().export_json(case), encoding="utf-8")
        click.echo(f"Wrote STIX 2.1 bundle -> {output_stix}")


def _build_platform_specs(
    sherlock_file: str | None,
    wmn_file: str | None,
    max_sites: int,
) -> list[PlatformSpec] | None:
    """Combine built-in JSON platform specs with optional Sherlock/WhatsMyName registries."""
    if not sherlock_file and not wmn_file:
        return None
    combined: list[PlatformSpec] = list(DEFAULT_PLATFORM_SPECS)
    seen = {spec.platform.strip().lower() for spec in combined}
    if sherlock_file:
        for spec in load_sherlock_specs(sherlock_file, max_sites=max_sites):
            key = spec.platform.strip().lower()
            if key not in seen:
                seen.add(key)
                combined.append(spec)
    if wmn_file:
        for spec in load_whatsmyname_specs(wmn_file, max_sites=max_sites):
            key = spec.platform.strip().lower()
            if key not in seen:
                seen.add(key)
                combined.append(spec)
    return combined


@app.command("scan")
@click.argument("query")
@click.option("--title", default=None, help="Investigation title.")
@click.option("--hops", default=2, show_default=True, type=int, help="Maximum pivot hops.")
@click.option("--db", default=None, help="SQLite database path.")
@click.option(
    "--sherlock-file",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to Sherlock data.json site registry.",
)
@click.option(
    "--wmn-file",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to WhatsMyName wmn-data.json site registry.",
)
@click.option(
    "--max-sites",
    default=50,
    show_default=True,
    type=int,
    help="Maximum sites loaded per external Sherlock/WMN file.",
)
@click.option(
    "--scrapling/--no-scrapling",
    default=True,
    show_default=True,
    help="Enable Scrapling public page & profile scraper.",
)
@click.option(
    "--dynamic/--no-dynamic",
    default=False,
    show_default=True,
    help="Use Scrapling DynamicFetcher (Playwright Chromium) for JS-rendered pages.",
)
def cmd_scan(
    query: str,
    title: str | None,
    hops: int,
    db: str | None,
    sherlock_file: str | None,
    wmn_file: str | None,
    max_sites: int,
    scrapling: bool,
    dynamic: bool,
) -> None:
    """Execute a multi-collector OSINT scan and resolve persona hierarchy trees."""
    db_path = _resolve_db_path(db)
    platforms = _build_platform_specs(sherlock_file=sherlock_file, wmn_file=wmn_file, max_sites=max_sites)

    async def _run() -> Case:
        async with CaseStorage(db_path) as store:
            registry = create_default_registry(
                include_scrapling=scrapling or dynamic,
                scrapling_dynamic=dynamic,
                username_platforms=platforms,
            )
            orchestrator = ScanOrchestrator(storage=store, registry=registry)
            case, _ = await orchestrator.run_scan(
                query=query,
                title=title,
                max_hops=hops,
            )
            return case

    case = asyncio.run(_run())
    click.echo(f"Case ID: {case.case_id} | Nodes: {len(case.nodes)} | Personas: {len(case.personas)}")
    for persona in case.personas:
        if persona.hierarchy_tree is not None:
            click.echo(render_hierarchy_ascii(persona.hierarchy_tree))


@app.command("scrape")
@click.argument("target")
@click.option(
    "--dynamic/--no-dynamic",
    default=False,
    show_default=True,
    help="Use Scrapling DynamicFetcher (Playwright Chromium) for public JS-rendered pages.",
)
@click.option("--db", default=None, help="SQLite database path.")
@click.option("--title", default=None, help="Investigation title.")
def cmd_scrape(target: str, dynamic: bool, db: str | None, title: str | None) -> None:
    """Scrape a public URL or username profile via Scrapling and persist SHA-256 evidence."""
    db_path = _resolve_db_path(db)

    async def _scrape() -> tuple[Case, list[str]]:
        async with CaseStorage(db_path) as store:
            case = await store.create_case(
                title=title or f"Scrapling Scrape: {target}",
                target_query=target,
            )
            collector = ScraplingCollector(use_dynamic_browser=dynamic)
            local_ledger = CustodyLedger(case_id=case.case_id)
            result = await collector.collect(
                query=target,
                case_id=case.case_id,
                ledger=local_ledger,
                storage=store,
            )
            await store.merge_collector_result(case.case_id, result)
            updated = await store.get_case(case.case_id)
            assert updated is not None
            if updated.nodes:
                KnowledgeGraphEngine().apply_to_case(updated)
                await AIAnalyst(provider="deterministic").analyze_case(
                    updated,
                    run_graph_disambiguation=False,
                )
            updated.status = CaseStatus.COMPLETED
            saved = await store.save_case(updated)
            return saved, result.errors

    case, errs = asyncio.run(_scrape())
    click.echo(
        f"Case ID: {case.case_id} | Nodes: {len(case.nodes)} | Evidence: {len(case.evidence_ledger)}"
    )
    for node in case.nodes:
        if node.entity_type in (EntityType.SOCIAL_PROFILE, EntityType.URL):
            attrs = node.attributes or {}
            disp = attrs.get("display_name") or node.label or node.value
            plat = node.platform or "Web"
            click.echo(f" - [{plat}] {disp} ({attrs.get('url', node.value)})")
            if attrs.get("bio"):
                click.echo(f"   Bio: {str(attrs['bio'])[:160]}")
            counts = [
                f"{k}={attrs[v]}"
                for k, v in (
                    ("followers", "follower_count"),
                    ("following", "following_count"),
                    ("posts", "post_count"),
                )
                if attrs.get(v) is not None
            ]
            if counts:
                click.echo(f"   Counts: {', '.join(counts)}")
            if attrs.get("mentions"):
                click.echo(f"   Mentions: {', '.join(attrs['mentions'][:8])}")
            if attrs.get("hashtags"):
                click.echo(f"   Hashtags: {', '.join(attrs['hashtags'][:8])}")
    for err in errs:
        click.echo(f"Notice: {err}")


@app.group("case")
def case_group() -> None:
    """Inspect and verify persisted investigation Cases."""


@case_group.command("list")
@click.option("--db", default=None, help="SQLite database path.")
def cmd_case_list(db: str | None) -> None:
    """List all Cases stored in SQLite."""
    db_path = _resolve_db_path(db)

    async def _list() -> list[Case]:
        async with CaseStorage(db_path) as store:
            return await store.list_cases()

    cases = asyncio.run(_list())
    if not cases:
        click.echo("No cases found.")
        return
    for c in cases:
        click.echo(
            f"{c.case_id} | {c.status.value} | query={c.target_query} | "
            f"nodes={len(c.nodes)} | personas={len(c.personas)} | {c.title}"
        )


@case_group.command("show")
@click.argument("case_id")
@click.option("--db", default=None, help="SQLite database path.")
def cmd_case_show(case_id: str, db: str | None) -> None:
    """Show details, hierarchy trees, and brief for CASE_ID."""
    db_path = _resolve_db_path(db)

    async def _get() -> Case | None:
        async with CaseStorage(db_path) as store:
            return await store.get_case(case_id)

    case = asyncio.run(_get())
    if case is None:
        click.echo(f"Error: Case '{case_id}' not found.", err=True)
        raise SystemExit(1)

    click.echo(f"Case: {case.title} [{case.case_id}] | Status: {case.status.value}")
    for persona in case.personas:
        if persona.hierarchy_tree is not None:
            click.echo(render_hierarchy_ascii(persona.hierarchy_tree))
    if case.ai_executive_brief:
        click.echo("\n" + case.ai_executive_brief)


@case_group.command("verify")
@click.argument("case_id")
@click.option("--db", default=None, help="SQLite database path.")
def cmd_case_verify(case_id: str, db: str | None) -> None:
    """Cryptographically verify the SHA-256 Chain of Custody for CASE_ID."""
    db_path = _resolve_db_path(db)

    async def _verify() -> tuple[Case | None, bool, list[str]]:
        async with CaseStorage(db_path) as store:
            c = await store.get_case(case_id)
            if c is None:
                return None, False, []
            ok, errs = await store.verify_case_custody(case_id)
            return c, ok, errs

    case, ok, violations = asyncio.run(_verify())
    if case is None:
        click.echo(f"Error: Case '{case_id}' not found.", err=True)
        raise SystemExit(1)

    if ok:
        click.echo(
            f"Custody VERIFIED (INTACT) for case {case_id} "
            f"({len(case.evidence_ledger)} evidence items)."
        )
    else:
        click.echo(f"Custody FAILED for case {case_id}: {'; '.join(violations)}", err=True)
        raise SystemExit(2)


@app.command("pivot")
@click.argument("case_id")
@click.argument("node_id")
@click.option("--db", default=None, help="SQLite database path.")
def cmd_pivot(case_id: str, node_id: str, db: str | None) -> None:
    """Pivot on NODE_ID inside CASE_ID and re-resolve persona clusters."""
    db_path = _resolve_db_path(db)

    async def _pivot() -> Case:
        async with CaseStorage(db_path) as store:
            orchestrator = ScanOrchestrator(storage=store)
            updated, _ = await orchestrator.pivot_on_node(case_id=case_id, node_id=node_id)
            return updated

    try:
        updated = asyncio.run(_pivot())
    except KeyError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1) from exc
    click.echo(
        f"Pivot complete for {case_id}: nodes={len(updated.nodes)}, personas={len(updated.personas)}"
    )


@app.command("report")
@click.argument("case_id")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["markdown", "stix"], case_sensitive=False),
    default="markdown",
    show_default=True,
)
@click.option("--output", default=None, help="Output file path (prints to stdout if omitted).")
@click.option("--db", default=None, help="SQLite database path.")
def cmd_report(case_id: str, fmt: str, output: str | None, db: str | None) -> None:
    """Export CASE_ID as a Markdown investigative dossier or STIX 2.1 JSON bundle."""
    db_path = _resolve_db_path(db)

    async def _get() -> Case | None:
        async with CaseStorage(db_path) as store:
            return await store.get_case(case_id)

    case = asyncio.run(_get())
    if case is None:
        click.echo(f"Error: Case '{case_id}' not found.", err=True)
        raise SystemExit(1)

    content = (
        MarkdownExporter().export(case, verify_custody=True)
        if fmt.lower() == "markdown"
        else STIXExporter().export_json(case)
    )
    if output:
        Path(output).write_text(content, encoding="utf-8")
        click.echo(f"Exported {fmt} report -> {output}")
    else:
        click.echo(content)


@app.command("tui")
@click.argument("case_id", required=False)
@click.option("--db", default=None, help="SQLite database path.")
@click.option("--snapshot", is_flag=True, help="Print terminal dashboard snapshot without blocking.")
def cmd_tui(case_id: str | None, db: str | None, snapshot: bool) -> None:
    """Launch the interactive OmniSINT terminal dashboard."""
    if case_id:
        db_path = _resolve_db_path(db)

        async def _get() -> Case | None:
            async with CaseStorage(db_path) as store:
                return await store.get_case(case_id)

        case = asyncio.run(_get())
        if case is None:
            click.echo(f"Error: Case '{case_id}' not found.", err=True)
            raise SystemExit(1)
    else:
        case, _ = build_demo_collision_case()

    rendered = launch_tui(case, interactive=not snapshot)
    click.echo(rendered)


@app.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8000, show_default=True, type=int)
@click.option("--db", default=None, help="SQLite database path.")
def cmd_serve(host: str, port: int, db: str | None) -> None:
    """Start the OmniSINT Web GUI & REST API server."""
    db_path = _resolve_db_path(db)
    storage = CaseStorage(db_path)
    web_app = create_app(storage=storage)
    if hasattr(web_app, "run"):
        web_app.run(host=host, port=port)  # pragma: no cover
    else:  # pragma: no cover
        import uvicorn  # type: ignore[import-untyped]

        uvicorn.run(web_app, host=host, port=port)


def run_cli(args: Sequence[str]) -> tuple[int, str]:
    """Invoke the OmniSINT CLI programmatically and return `(exit_code, output)`."""
    from click.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(app, list(args))
    return result.exit_code, result.output


if __name__ == "__main__":  # pragma: no cover
    app()
