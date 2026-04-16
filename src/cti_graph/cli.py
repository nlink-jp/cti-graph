"""CLI entry point for cti-graph."""

from __future__ import annotations

from pathlib import Path

import click
import structlog

from cti_graph import __version__
from cti_graph.config import load_config
from cti_graph.db.repository import SQLiteRepository

logger = structlog.get_logger(__name__)


@click.group()
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to config.toml",
)
@click.pass_context
def main(ctx: click.Context, config_path: Path | None) -> None:
    """cti-graph: Local-first threat intelligence attack graph analysis."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config_path)


@main.command()
def version() -> None:
    """Show version."""
    click.echo(f"cti-graph {__version__}")


@main.command("init-db")
@click.pass_context
def init_db(ctx: click.Context) -> None:
    """Initialise the SQLite database with the graph schema."""
    cfg = ctx.obj["config"]
    repo = SQLiteRepository(cfg.db_path)
    try:
        repo.init_schema()
        click.echo(f"Database initialised at {cfg.db_path}")
    finally:
        repo.close()


@main.command()
@click.option(
    "--bundle",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to a single STIX bundle JSON file",
)
@click.option(
    "--pir",
    "pir_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to PIR JSON file",
)
@click.pass_context
def etl(ctx: click.Context, bundle: Path | None, pir_path: Path | None) -> None:
    """Run the ETL pipeline to ingest STIX data."""
    from cti_graph.etl.worker import ETLWorker
    from cti_graph.pir.filter import PIRFilter
    from cti_graph.stix.parser import load_bundle_from_file, load_bundles_from_dir

    cfg = ctx.obj["config"]

    # Load PIR
    if pir_path:
        pir_filter = PIRFilter.from_file(pir_path)
    else:
        pir_filter = PIRFilter.empty()

    # Load STIX objects
    if bundle:
        objects = load_bundle_from_file(bundle)
    else:
        stix_dir = cfg.stix_dir
        if not stix_dir.is_dir():
            click.echo(f"STIX landing directory not found: {stix_dir}", err=True)
            raise SystemExit(1)
        objects = load_bundles_from_dir(stix_dir, tlp_max=cfg.stix.tlp_max)

    if not objects:
        click.echo("No STIX objects to process.")
        return

    # Run ETL
    repo = SQLiteRepository(cfg.db_path)
    try:
        repo.init_schema()
        worker = ETLWorker(repo, pir_filter, tlp_max_level=cfg.stix.tlp_max)
        stats = worker.process_bundle(objects)
        click.echo(f"ETL complete: {stats}")
    finally:
        repo.close()


@main.command()
@click.pass_context
def serve(ctx: click.Context) -> None:
    """Start the analysis API server."""
    cfg = ctx.obj["config"]
    click.echo(f"API server: {cfg.api.host}:{cfg.api.port}")
    click.echo("API server not yet implemented (Phase 3)")
