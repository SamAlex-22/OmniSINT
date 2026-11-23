"""Unit tests for the labelled disambiguation benchmark harness."""

from __future__ import annotations

import unittest

from omnisint.intelligence.benchmark import (
    evaluate_clustering,
    run_disambiguation_benchmark,
)


class TestDisambiguationBenchmark(unittest.TestCase):
    """Verify entity-resolution precision, recall, F1, and Adjusted Rand Index."""

    def test_evaluate_clustering_exact_and_split_cases(self) -> None:
        perfect = evaluate_clustering([["a", "b"], ["c"]], {"a": "g1", "b": "g1", "c": "g2"})
        self.assertEqual(perfect.pairwise_f1, 1.0)
        self.assertEqual(perfect.adjusted_rand_index, 1.0)

    def test_default_disambiguation_benchmark_meets_accuracy_targets(self) -> None:
        aggregate, case_results = run_disambiguation_benchmark()
        self.assertEqual(len(case_results), 3)
        self.assertGreaterEqual(aggregate.pairwise_f1, 0.90)
        self.assertGreaterEqual(aggregate.adjusted_rand_index, 0.85)
        for res in case_results:
            self.assertEqual(res.predicted_cluster_count, res.expected_cluster_count)


if __name__ == "__main__":
    unittest.main()
