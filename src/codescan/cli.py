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
    fixtures: str | None = typer.Option(
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
    whitebox: bool = typer.Option(
        False, "--whitebox",
        help="Review the target repo's source with the built-in OpenHack AI "
             "engine (clones + scans it). Needs AI enabled and git; Snyk/Xray "
             "are skipped when their credentials aren't set. Use with --repo.",
    ),
) -> None:
    """Run the full pipeline and write a ServiceNow VR import file."""
    configure()
    if whitebox and no_ai:
        raise typer.BadParameter("--whitebox needs the AI engine; drop --no-ai.")
    cfg = Config.load(config)
    if sn_format:
        cfg.servicenow.format = sn_format
    if repo:
        # Scope to specific GitHub repos -> GitHub source, live ingest.
        cfg.source.provider = "github"
        cfg.github.repos = list(repo)
        fixtures = None
    if whitebox:
        # Turn on the built-in whitebox engine for a live scan of the source.
        cfg.source.provider = "github"
        cfg.openhack.auto = True
        cfg.openhack.clone = True
        cfg.openhack.command = []          # force the built-in engine
        fixtures = None
    pipeline = Pipeline(cfg, offline=offline, use_ai=not no_ai)
    result = pipeline.run(fixtures=fixtures, out_path=out, state_path=state)
    from .servicenow import ServiceNowExporter
    written = ServiceNowExporter(cfg.servicenow).output_path(out)

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

    console.print(f"\nServiceNow import written to [green]{written}[/green]")


@app.command()
def serve(
    config: str = typer.Option("config/config.example.yaml", help="Path to config YAML."),
    fixtures: str = typer.Option("fixtures", help="Fixtures dir for offline scans."),
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8000),
    ai: bool = typer.Option(False, "--ai", help="Enable the AI stages (needs FOUNDRY_API_KEY)."),
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
def calibration(
    config: str = typer.Option("config/config.example.yaml", help="Path to config YAML."),
    state: str = typer.Option("validation_state.json", help="Validation-state store path."),
) -> None:
    """Grade past risk scores against analysts' confirm / false-positive decisions."""
    configure()
    from .calibration import calibration_report, drift_alerts
    from .validation import open_state_store

    cfg = Config.load(config)
    report = calibration_report(open_state_store(cfg.storage, state))

    if not report["decisions"]:
        console.print("No manual confirmed/false-positive decisions recorded yet — "
                      "triage findings in the UI (or ServiceNow) and re-run.")
        return

    for alert in drift_alerts(report, cfg.calibration):
        console.print(f"[bold red]⚠ DRIFT[/bold red] {alert}")

    rate = f"{report['confirm_rate']:.0%}" if report["confirm_rate"] is not None else "—"
    console.print(f"[bold]codescan calibration[/bold]: {report['decisions']} manual decisions "
                  f"({report['confirmed']} confirmed, {report['false_positives']} false "
                  f"positives, {rate} confirm rate)")
    if report["unscored"]:
        console.print(f"  {report['unscored']} decision(s) predate score snapshots "
                      "and are excluded from the buckets below.")

    table = Table(title="Confirm rate by predicted risk score (should rise with the bucket)")
    table.add_column("Predicted score")
    table.add_column("Decisions", justify="right")
    table.add_column("Confirmed", justify="right")
    table.add_column("False positives", justify="right")
    table.add_column("Confirm rate", justify="right")
    for b in report["buckets"]:
        table.add_row(b["bucket"], str(b["total"]), str(b["confirmed"]),
                      str(b["false_positive"]),
                      f"{b['confirm_rate']:.0%}" if b["confirm_rate"] is not None else "—")
    console.print(table)

    mc, mf = report["mean_score_confirmed"], report["mean_score_false_positive"]
    if mc is not None and mf is not None:
        console.print(f"Mean predicted score: confirmed {mc} vs false positive {mf} "
                      f"(separation {mc - mf:+.1f})")
    if report["noisy_keys"]:
        console.print("\n[bold]Noisiest weakness families / components[/bold] "
                      "(mostly dismissed as false positives)")
        for k in report["noisy_keys"]:
            console.print(f"  {k['key']}: {k['false_positive']} FP vs "
                          f"{k['confirmed']} confirmed ({k['fp_rate']:.0%} FP rate)")


def _read_import_records(out: str) -> list[dict]:
    """Load records from a ServiceNow import file (JSON or CSV).

    Resolves the given path, or its `.csv`/`.json` sibling when the exact one is
    absent — so `summary` works whether the scan wrote CSV (the default) or JSON.
    """
    import csv

    path = Path(out)
    if not path.exists():
        for alt in (path.with_suffix(".csv"), path.with_suffix(".json")):
            if alt.exists():
                path = alt
                break
        else:
            raise typer.BadParameter(f"no import file at {out} (nor its .csv/.json sibling)")
    if path.suffix.lower() == ".csv":
        return list(csv.DictReader(path.open(encoding="utf-8")))
    return json.loads(path.read_text(encoding="utf-8")).get("records", [])


@app.command()
def summary(out: str = typer.Option("servicenow_import.json")) -> None:
    """Print a summary of an existing ServiceNow import file (JSON or CSV)."""
    records = _read_import_records(out)
    console.print(f"{len(records)} vulnerable items")
    for r in records[:20]:
        score = float(r.get("risk_score") or 0)
        console.print(f"  {score:>5.0f} {r.get('risk_rating', ''):<8} "
                      f"{r.get('state', ''):<22} {(r.get('short_description') or '')[:60]}")


if __name__ == "__main__":
    app()
