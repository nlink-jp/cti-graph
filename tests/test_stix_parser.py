"""Tests for STIX bundle parser."""

from __future__ import annotations

import json
from pathlib import Path

from cti_graph.stix.parser import (
    classify_objects,
    load_bundle_from_file,
    load_bundles_from_dir,
    parse_bundle,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_bundle_from_file():
    objects = load_bundle_from_file(FIXTURES / "sample_bundle.json")
    assert len(objects) > 0
    types = {o["type"] for o in objects}
    assert "threat-actor" in types
    assert "attack-pattern" in types
    assert "relationship" in types


def test_parse_bundle_filters_unsupported():
    bundle = {
        "type": "bundle",
        "id": "bundle--2ae6cf24-1f98-451a-97da-25f30b034201",
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": "identity--9c30c566-1195-470c-be19-15cc272eef8d",
                "created": "2025-01-01T00:00:00Z",
                "modified": "2025-01-01T00:00:00Z",
                "name": "Test Identity",
                "identity_class": "organization",
            },
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": "attack-pattern--22e1de21-7e5d-4f04-87c9-2493fdecdd23",
                "created": "2025-01-01T00:00:00Z",
                "modified": "2025-01-01T00:00:00Z",
                "name": "Test Pattern",
            },
        ],
    }
    objects = parse_bundle(bundle)
    assert len(objects) == 1
    assert objects[0]["type"] == "attack-pattern"


def test_parse_bundle_handles_invalid_gracefully():
    bundle = {
        "type": "bundle",
        "id": "bundle--6bb098db-b52e-4cf6-b24e-2de89fce5664",
        "objects": [
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                # missing required fields (id, name, created, modified)
            },
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": "attack-pattern--4bb66db5-ef98-40bc-b48e-93e60d508fa1",
                "created": "2025-01-01T00:00:00Z",
                "modified": "2025-01-01T00:00:00Z",
                "name": "Valid Pattern",
            },
        ],
    }
    objects = parse_bundle(bundle)
    assert len(objects) == 1


def test_classify_objects():
    objects = load_bundle_from_file(FIXTURES / "sample_bundle.json")
    by_type = classify_objects(objects)

    assert "threat-actor" in by_type
    assert "attack-pattern" in by_type
    assert "relationship" in by_type
    assert len(by_type["attack-pattern"]) == 2


def test_load_bundles_from_dir_tlp_filter(tmp_path):
    green_id = "indicator--62911417-6316-426f-a9b8-6c91d3e0289e"
    red_id = "indicator--214445e9-9578-45bf-ba04-bf6c73e5a3af"

    bundle = {
        "type": "bundle",
        "id": "bundle--87fd4e9c-be3b-4e18-94e5-62b246ceadea",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": green_id,
                "created": "2025-01-01T00:00:00Z",
                "modified": "2025-01-01T00:00:00Z",
                "name": "Green indicator",
                "pattern": "[ipv4-addr:value = '10.0.0.1']",
                "pattern_type": "stix",
                "valid_from": "2025-01-01T00:00:00Z",
                "object_marking_refs": ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"],
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": red_id,
                "created": "2025-01-01T00:00:00Z",
                "modified": "2025-01-01T00:00:00Z",
                "name": "Red indicator",
                "pattern": "[ipv4-addr:value = '10.0.0.2']",
                "pattern_type": "stix",
                "valid_from": "2025-01-01T00:00:00Z",
                "object_marking_refs": ["marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"],
            },
        ],
    }
    (tmp_path / "test.json").write_text(json.dumps(bundle))

    # TLP max = amber -> red should be excluded
    objects = load_bundles_from_dir(tmp_path, tlp_max="amber")
    ids = {o["id"] for o in objects}
    assert green_id in ids
    assert red_id not in ids


def test_load_bundles_from_dir_empty(tmp_path):
    objects = load_bundles_from_dir(tmp_path)
    assert objects == []
