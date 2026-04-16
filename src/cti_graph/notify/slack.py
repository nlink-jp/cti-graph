"""Slack webhook notifications.

Detects changes in choke-point scores since the last ETL run
and sends a Slack notification when significant changes occur.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

# Minimum relative change required to trigger a notification (10%)
_CHANGE_THRESHOLD = 0.10


def notify_etl_complete(
    webhook_url: str,
    stats: dict[str, int],
    choke_rows: list[dict],
    prev_choke_rows: list[dict],
) -> bool:
    """Send a Slack notification about choke-point score changes after ETL.

    Only sends when at least one asset's score changed by >= 10%.

    Returns True if a notification was sent, False if skipped.
    """
    if not webhook_url:
        return False

    changed = _detect_changes(choke_rows, prev_choke_rows)
    if not changed:
        logger.info("slack_notify_skipped", reason="no significant choke score change")
        return False

    blocks = _build_etl_blocks(stats, changed)
    return _post(webhook_url, {"blocks": blocks})


def _detect_changes(
    current: list[dict],
    previous: list[dict],
) -> list[dict]:
    """Return assets whose choke score changed by _CHANGE_THRESHOLD or more."""
    prev_map = {r["asset_id"]: r["choke_score"] for r in previous}
    changed = []

    for row in current:
        asset_id = row["asset_id"]
        prev_score = prev_map.get(asset_id)

        if prev_score is None:
            changed.append({**row, "change": "new", "prev_score": None})
        elif prev_score == 0:
            if row["choke_score"] > 0:
                changed.append({**row, "change": "increased", "prev_score": prev_score})
        else:
            ratio = abs(row["choke_score"] - prev_score) / prev_score
            if ratio >= _CHANGE_THRESHOLD:
                direction = "increased" if row["choke_score"] > prev_score else "decreased"
                changed.append({**row, "change": direction, "prev_score": prev_score})

    return changed


def _build_etl_blocks(stats: dict[str, int], changed: list[dict]) -> list[dict]:
    """Build a Slack Block Kit message payload."""
    actor_count = stats.get("threat_actors", 0)
    ttp_count = stats.get("ttps", 0)

    header = (
        f"*cti-graph — Choke-Point Score Change Detected*\nETL complete: *{actor_count}* actor(s), *{ttp_count}* TTP(s)"
    )

    lines = []
    for row in changed[:5]:
        if row["change"] == "new":
            icon = "[NEW]"
        elif row["change"] == "increased":
            icon = "[UP]"
        else:
            icon = "[DOWN]"
        prev = f"(prev: {row['prev_score']:.1f})" if row["prev_score"] is not None else "(new)"
        lines.append(
            f"{icon} *{row['asset_name']}*  "
            f"score: {row['choke_score']:.1f} {prev}  "
            f"targeting actors: {row['targeting_actor_count']}"
        )

    if len(changed) > 5:
        lines.append(f"_...and {len(changed) - 5} more_")

    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": header}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
    ]


def _post(webhook_url: str, payload: dict[str, Any]) -> bool:
    """POST payload to the Slack Incoming Webhook."""
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(webhook_url, json=payload)
            resp.raise_for_status()
            return True
    except Exception as exc:
        logger.error("slack_notify_failed", error=str(exc))
        return False
