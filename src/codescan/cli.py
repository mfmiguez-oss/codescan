"""codescan CLI."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .config import Config
from .logging_setup import configure
from .pipeline import Pipeline

app = typer.Typer(add_completion=False, help="Enterprise code-scanning pipeline.")
console = Console()


def _print_chain(chain: dict) -> None:
    console.print(
        f"  [{chain['chain_id']}] score {chain.get('chain_score')} "
        f"({chain.get('likelihood')}): {chain.get('narrative', '')[:120]}"
    )


@app.command()
def scan(
    config: str = typer.Option("config/config.example.yaml", help="Path to config YAML."),
    fixtures: str = typer.Option(
        None, help="Directory of scanner exports to run offline instead of live APIs."
    ),
    out: str = typer.Option("servicenow_import.json", help="ServiceNow import output path."),
    state: str = typer.Option("validation_state.json", help="Validation-state store path."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip the AI exploitability stage."),
    offline: bool = typer.Option(
        False, "--offline", help="Skip network enrichment (KEV/EPSS)."
    ),
    sn_format: str = typer.Option(
        None, "--sn-format", help="ServiceNow output format: json|csv (overrides config)."
    ),
    repo: list[str] = typer.Option(
        None, "--repo",
        help="Target specific GitHub repo(s) 'owner/name'. Implies GitHub source "
             "and a live scan. Repeatable.",
    ),
) -> None:
    """Run the full pipeline and write a ServiceNow VR import file."""
    configure()
    cfg = Config.load(config)
    if sn_format:
        cfg.servicenow.format = sn_format
    if repo:
        # Scope to specific GitHub repos -> GitHub source, live ingest.
        cfg.source.provider = "github"
        cfg.github.repos = list(repo)
        fixtures = None
    pipeline = Pipeline(cfg, offline=offline, use_ai=not no_ai)
    result = pipeline.run(fixtures=fixtures, out_path=out, state_path=state)

    summary = result.summary()
    console.print(f"[bold]codescan[/bold]: {summary['findings']} findings across "
                  f"{summary['repos']} repos, {summary['chains']} attack chains, "
                  f"{summary['kev']} actively exploited (KEV)")

    table = Table(title="Top risk (ServiceNow VR queue order)")
    table.add_column("Risk", justify="right")
    table.add_column("State")
    table.add_column("Title")
    for row in summary["top_risk"]:
        table.add_row(f"{row['score']:.0f}", row["state"], row["title"][:70])
    console.print(table)

    if result.chains:
        console.print("\n[bold]Attack chains[/bold]")
        for chain in result.chains:
            _print_chain(chain)

    console.print(f"\nServiceNow import written to [green]{out}[/green]")


@app.command()
def serve(
    config: str = typer.Option("config/config.example.yaml", help="Path to config YAML."),
    fixtures: str = typer.Option("fixtures", help="Fixtures dir for offline scans."),
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8000),
    ai: bool = typer.Option(False, "--ai", help="Enable the AI stages (needs ANTHROPIC_API_KEY)."),
    live: bool = typer.Option(False, "--live", help="Scan live systems instead of fixtures."),
) -> None:
    """Launch the web UI (analyst triage dashboard)."""
    configure()
    import uvicorn

    from .web import create_app

    application = create_app(
        config_path=config,
        fixtures=fixtures,
        live=live,
        use_ai=ai,
        offline=not ai,
    )
    console.print(f"codescan UI on [green]http://{host}:{port}[/green] "
                  f"({'live' if live else 'fixtures'}, AI {'on' if ai else 'off'})")
    uvicorn.run(application, host=host, port=port)


@app.command()
def summary(out: str = typer.Option("servicenow_import.json")) -> None:
    """Print a summary of an existing ServiceNow import file."""
    records = json.loads(Path(out).read_text(encoding="utf-8")).get("records", [])
    console.print(f"{len(records)} vulnerable items")
    for r in records[:20]:
        console.print(f"  {r['risk_score']:>5} {r['risk_rating']:<8} "
                      f"{r['state']:<22} {r['short_description'][:60]}")


if __name__ == "__main__":
    app()
