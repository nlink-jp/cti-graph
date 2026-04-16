"""Tests for external integration clients (OpenCTI, Caldera, Slack)."""

from __future__ import annotations

import httpx
import respx

from cti_graph.caldera.client import create_adversary, get_adversaries, sync_actor_ttps
from cti_graph.notify.slack import _detect_changes, notify_etl_complete

# ---------------------------------------------------------------------------
# Caldera client tests
# ---------------------------------------------------------------------------


class TestCalderaGetAdversaries:
    @respx.mock
    def test_success(self):
        respx.get("http://caldera.test/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json=[{"name": "test", "adversary_id": "adv-1"}])
        )
        result = get_adversaries("http://caldera.test", "key")
        assert len(result) == 1
        assert result[0]["adversary_id"] == "adv-1"

    @respx.mock
    def test_failure(self):
        respx.get("http://caldera.test/api/v2/adversaries").mock(return_value=httpx.Response(500))
        result = get_adversaries("http://caldera.test", "key")
        assert result == []


class TestCalderaCreateAdversary:
    @respx.mock
    def test_success(self):
        respx.post("http://caldera.test/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"adversary_id": "new-1", "name": "test"})
        )
        result = create_adversary("http://caldera.test", "key", "test", "desc", ["a1"])
        assert result is not None
        assert result["adversary_id"] == "new-1"


class TestCalderaSyncActorTTPs:
    @respx.mock
    def test_create_new(self):
        respx.get("http://caldera.test/api/v2/adversaries").mock(return_value=httpx.Response(200, json=[]))
        respx.post("http://caldera.test/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"adversary_id": "new-1"})
        )

        ttp_rows = [
            {"src_ttp_stix_id": "ttp-1", "dst_ttp_stix_id": "ttp-2"},
            {"src_ttp_stix_id": "ttp-2", "dst_ttp_stix_id": "ttp-3"},
        ]
        result = sync_actor_ttps("http://caldera.test", "key", "actor-1", ttp_rows)
        assert result["action"] == "created"
        assert result["ability_count"] == 3

    @respx.mock
    def test_update_existing(self):
        respx.get("http://caldera.test/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json=[{"name": "cti-graph-actor-1", "adversary_id": "adv-1"}])
        )
        respx.patch("http://caldera.test/api/v2/adversaries/adv-1").mock(return_value=httpx.Response(200, json={}))

        result = sync_actor_ttps(
            "http://caldera.test",
            "key",
            "actor-1",
            [{"src_ttp_stix_id": "ttp-1", "dst_ttp_stix_id": "ttp-2"}],
        )
        assert result["action"] == "updated"


# ---------------------------------------------------------------------------
# Slack notification tests
# ---------------------------------------------------------------------------


class TestDetectChanges:
    def test_new_asset(self):
        current = [{"asset_id": "a1", "asset_name": "Web", "choke_score": 10.0, "targeting_actor_count": 2}]
        changed = _detect_changes(current, [])
        assert len(changed) == 1
        assert changed[0]["change"] == "new"

    def test_increased_score(self):
        current = [{"asset_id": "a1", "asset_name": "Web", "choke_score": 15.0, "targeting_actor_count": 3}]
        previous = [{"asset_id": "a1", "choke_score": 10.0}]
        changed = _detect_changes(current, previous)
        assert len(changed) == 1
        assert changed[0]["change"] == "increased"

    def test_decreased_score(self):
        current = [{"asset_id": "a1", "asset_name": "Web", "choke_score": 5.0, "targeting_actor_count": 1}]
        previous = [{"asset_id": "a1", "choke_score": 10.0}]
        changed = _detect_changes(current, previous)
        assert len(changed) == 1
        assert changed[0]["change"] == "decreased"

    def test_no_significant_change(self):
        current = [{"asset_id": "a1", "asset_name": "Web", "choke_score": 10.5, "targeting_actor_count": 2}]
        previous = [{"asset_id": "a1", "choke_score": 10.0}]
        changed = _detect_changes(current, previous)
        assert changed == []

    def test_zero_to_positive(self):
        current = [{"asset_id": "a1", "asset_name": "Web", "choke_score": 5.0, "targeting_actor_count": 1}]
        previous = [{"asset_id": "a1", "choke_score": 0}]
        changed = _detect_changes(current, previous)
        assert len(changed) == 1
        assert changed[0]["change"] == "increased"


class TestNotifyETLComplete:
    def test_no_webhook(self):
        assert notify_etl_complete("", {}, [], []) is False

    @respx.mock
    def test_sends_on_change(self):
        respx.post("https://hooks.slack.com/test").mock(return_value=httpx.Response(200))

        stats = {"threat_actors": 1, "ttps": 5}
        current = [{"asset_id": "a1", "asset_name": "Web", "choke_score": 20.0, "targeting_actor_count": 3}]
        previous = [{"asset_id": "a1", "choke_score": 10.0}]

        result = notify_etl_complete("https://hooks.slack.com/test", stats, current, previous)
        assert result is True

    def test_skips_when_no_change(self):
        stats = {"threat_actors": 1, "ttps": 5}
        current = [{"asset_id": "a1", "asset_name": "Web", "choke_score": 10.0, "targeting_actor_count": 2}]
        previous = [{"asset_id": "a1", "choke_score": 10.0}]

        result = notify_etl_complete("https://hooks.slack.com/test", stats, current, previous)
        assert result is False


# ---------------------------------------------------------------------------
# OpenCTI client tests (basic — full tests need mock OpenCTI server)
# ---------------------------------------------------------------------------


class TestOpenCTIClient:
    def test_skip_when_not_configured(self):
        from cti_graph.opencti.client import fetch_stix_bundle

        result = fetch_stix_bundle("", "", limit=10)
        assert result == []

    @respx.mock
    def test_rest_fallback(self):
        from cti_graph.opencti.client import _fetch_via_rest

        respx.post("https://opencti.test/graphql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "stixCoreObjects": {
                            "edges": [
                                {"node": {"toStix": {"type": "attack-pattern", "id": "ap--1"}}},
                            ]
                        }
                    }
                },
            )
        )
        result = _fetch_via_rest("https://opencti.test", "token", limit=10)
        assert len(result) == 1
        assert result[0]["type"] == "attack-pattern"
