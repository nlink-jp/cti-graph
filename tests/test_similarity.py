"""Tests for incident similarity analysis."""

from __future__ import annotations

from cti_graph.analysis.similarity import (
    bfs_reachable,
    build_followedby_graph,
    hybrid_score,
    jaccard_ttp,
    transition_coverage,
)


class TestJaccardTTP:
    def test_identical_sets(self):
        assert jaccard_ttp({"a", "b"}, {"a", "b"}) == 1.0

    def test_disjoint_sets(self):
        assert jaccard_ttp({"a"}, {"b"}) == 0.0

    def test_partial_overlap(self):
        assert jaccard_ttp({"a", "b"}, {"b", "c"}) == 1 / 3

    def test_empty_sets(self):
        assert jaccard_ttp(set(), set()) == 1.0

    def test_one_empty(self):
        assert jaccard_ttp({"a"}, set()) == 0.0


class TestBFSReachable:
    def test_basic(self):
        graph = {"a": {"b"}, "b": {"c"}, "c": {"d"}}
        reachable = bfs_reachable(graph, {"a"}, max_hops=2)
        assert reachable == {"a", "b", "c"}

    def test_zero_hops(self):
        graph = {"a": {"b"}}
        reachable = bfs_reachable(graph, {"a"}, max_hops=0)
        assert reachable == {"a"}

    def test_cycle(self):
        graph = {"a": {"b"}, "b": {"a"}}
        reachable = bfs_reachable(graph, {"a"}, max_hops=10)
        assert reachable == {"a", "b"}

    def test_multiple_starts(self):
        graph = {"a": {"c"}, "b": {"d"}}
        reachable = bfs_reachable(graph, {"a", "b"}, max_hops=1)
        assert reachable == {"a", "b", "c", "d"}


class TestTransitionCoverage:
    def test_full_coverage(self):
        graph = {"a": {"b"}, "b": {"c"}}
        assert transition_coverage({"a"}, {"a", "b", "c"}, graph, max_hops=2) == 1.0

    def test_partial_coverage(self):
        graph = {"a": {"b"}}
        # c is not reachable
        assert transition_coverage({"a"}, {"b", "c"}, graph, max_hops=1) == 0.5

    def test_empty_ref(self):
        assert transition_coverage({"a"}, set(), {}, max_hops=2) == 1.0

    def test_no_graph(self):
        # Only direct membership counts
        assert transition_coverage({"a", "b"}, {"a", "b", "c"}, {}, max_hops=2) == 2 / 3


class TestBuildFollowedByGraph:
    def test_basic(self):
        rows = [
            {"src_ttp_stix_id": "t1", "dst_ttp_stix_id": "t2"},
            {"src_ttp_stix_id": "t2", "dst_ttp_stix_id": "t3"},
            {"src_ttp_stix_id": "t1", "dst_ttp_stix_id": "t3"},
        ]
        graph = build_followedby_graph(rows)
        assert graph["t1"] == {"t2", "t3"}
        assert graph["t2"] == {"t3"}


class TestHybridScore:
    def test_balanced(self):
        # Example from HLD: incident=[A,C], ref=[A,B,C], A->B->C in graph
        graph = {"A": {"B"}, "B": {"C"}}
        score = hybrid_score({"A", "C"}, {"A", "B", "C"}, graph, alpha=0.5, max_hops=2)
        # jaccard = 2/3, coverage = 1.0
        expected = 0.5 * (2 / 3) + 0.5 * 1.0
        assert abs(score - expected) < 0.01

    def test_alpha_zero(self):
        # Only transition coverage
        graph = {"A": {"B"}}
        score = hybrid_score({"A"}, {"A", "B"}, graph, alpha=0.0, max_hops=1)
        assert score == 1.0

    def test_alpha_one(self):
        # Only jaccard
        score = hybrid_score({"A", "B"}, {"A", "B"}, {}, alpha=1.0, max_hops=1)
        assert score == 1.0
