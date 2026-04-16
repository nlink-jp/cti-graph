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
@click.pass_context
def etl(ctx: click.Context, bundle: Path | None) -> None:
    """Run the ETL pipeline to ingest STIX data."""
    cfg = ctx.obj["config"]

    if bundle:
        source = bundle
    else:
        source = cfg.stix_dir
        if not source.is_dir():
            click.echo(f"STIX landing directory not found: {source}", err=True)
            raise SystemExit(1)

    click.echo(f"ETL source: {source}")
    click.echo("ETL pipeline not yet implemented (Phase 2)")


@main.command()
@click.pass_context
def serve(ctx: click.Context) -> None:
    """Start the analysis API server."""
    cfg = ctx.obj["config"]
    click.echo(f"API server: {cfg.api.host}:{cfg.api.port}")
    click.echo("API server not yet implemented (Phase 3)")
