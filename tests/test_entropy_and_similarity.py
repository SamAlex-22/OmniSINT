"""Unit tests for Task 3: Shannon Entropy, Handle Rarity, Multi-Modal Similarity & Temporal Correlation."""

from __future__ import annotations

import unittest

from omnisint.core.models import EntityNode, EntityType
from omnisint.intelligence.entropy import (
    analyze_handle_entropy,
    compute_rarity_score,
    enrich_node_entropy,
    estimate_collision_probability,
    shannon_entropy,
    tokenize_handle,
)
from omnisint.intelligence.similarity import (
    avatar_hash_similarity,
    compare_handles,
    compute_dhash_from_bytes,
    compute_dhash_from_pixels,
    hamming_distance_hex,
    jaro_winkler_similarity,
    normalized_levenshtein,
    token_swap_similarity,
)
from omnisint.intelligence.temporal import (
    build_temporal_profile,
    correlate_timestamps,
    hourly_cosine_similarity,
)


class TestEntropySimilarityAndTemporal(unittest.TestCase):
    """Test suite for mathematical entity disambiguation primitives (Task 3)."""

    def test_tokenize_handle_and_shannon_entropy(self) -> None:
        self.assertEqual(
            tokenize_handle("JohnDoe_Sec99@proton.me"),
            ["john", "doe", "sec", "99"],
        )
        # "aaaa" has 0 bits of entropy; "abcd" has 2.0 bits of entropy
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0, places=3)

    def test_handle_rarity_penalizes_common_names_and_rewards_unique_handles(self) -> None:
        common_metrics = analyze_handle_entropy("john_smith")
        multinational_common = analyze_handle_entropy("rahul_sharma")
        rare_metrics = analyze_handle_entropy("x7_krypton_99")

        self.assertLess(common_metrics.rarity_score, 0.35)
        self.assertLess(multinational_common.rarity_score, 0.35)
        self.assertTrue(common_metrics.is_high_collision_risk)
        self.assertTrue(multinational_common.is_high_collision_risk)
        self.assertGreater(rare_metrics.rarity_score, 0.70)
        self.assertFalse(rare_metrics.is_high_collision_risk)
        self.assertGreater(
            estimate_collision_probability("john_smith"),
            estimate_collision_probability("x7_krypton_99"),
        )

        # Verify EntityNode enrichment
        node = EntityNode(entity_type=EntityType.USERNAME, value="x7_krypton_99")
        enrich_node_entropy(node)
        self.assertEqual(node.entropy_score, rare_metrics.shannon_entropy)
        self.assertEqual(node.rarity_score, rare_metrics.rarity_score)

    def test_string_and_token_swap_similarity(self) -> None:
        # Jaro-Winkler and Levenshtein on minor typo / suffix handles
        jw = jaro_winkler_similarity("krypton_sec", "krypton_sec_dev")
        lev = normalized_levenshtein("krypton_sec", "krypton_sec_dev")
        self.assertGreater(jw, 0.85)
        self.assertGreater(lev, 0.70)

        # Token-swap across delimited and delimiter-free handles: john_doe_sec <-> doejohnsec
        tswap_compact = token_swap_similarity("john_doe_sec", "doejohnsec")
        tswap_reordered = token_swap_similarity("john_doe_sec", "sec_john_doe")
        self.assertEqual(tswap_compact, 1.0)
        self.assertEqual(tswap_reordered, 1.0)

        # Unrelated handles should score low
        self.assertLess(token_swap_similarity("x7_krypton_99", "alice_baker_nyc"), 0.35)

    def test_perceptual_avatar_dhash_and_multi_modal_comparison(self) -> None:
        # Construct an 8x9 pixel gradient grid and a nearly identical grid (1 pixel changed)
        grid_a = [[(row * 20 + col * 10) % 255 for col in range(9)] for row in range(8)]
        grid_b = [list(row) for row in grid_a]
        grid_b[0][0] = 250  # Flip at most 1 gradient bit

        hash_a = compute_dhash_from_pixels(grid_a)
        hash_b = compute_dhash_from_pixels(grid_b)
        self.assertEqual(len(hash_a), 16)
        self.assertLessEqual(hamming_distance_hex(hash_a, hash_b), 2)
        self.assertGreaterEqual(avatar_hash_similarity(hash_a, hash_b), 0.95)

        # Byte-stream dHash determinism
        bytes_hash_1 = compute_dhash_from_bytes(b"SVG_AVATAR_PAYLOAD_V1_" * 20)
        bytes_hash_2 = compute_dhash_from_bytes(b"SVG_AVATAR_PAYLOAD_V1_" * 20)
        self.assertEqual(bytes_hash_1, bytes_hash_2)

        # Multi-modal compare_handles: token-swapped rare handle + matching avatar hash
        sim_result = compare_handles(
            "krypton_sec_x7",
            "x7kryptonsec",
            avatar_hash_1=hash_a,
            avatar_hash_2=hash_b,
        )
        self.assertGreaterEqual(sim_result.token_swap, 0.95)
        assert sim_result.avatar_similarity is not None
        self.assertGreaterEqual(sim_result.avatar_similarity, 0.95)
        self.assertGreater(sim_result.composite_score, 0.88)
        self.assertIn("avatar dHash", sim_result.rationale)

        # Common name match without avatar should have lower rarity_weight than rare handle match
        common_sim = compare_handles("john_smith", "john_smith_1")
        self.assertLess(common_sim.rarity_weight, sim_result.rarity_weight)
        self.assertGreater(compute_rarity_score("krypton_sec_x7"), compute_rarity_score("john_smith"))

    def test_temporal_profile_and_timezone_correlation(self) -> None:
        # Persona A (GitHub commits in UTC+05:30 afternoon/evening)
        commits_persona_a = [
            "2026-05-04T14:15:00+05:30",  # 08:45 UTC
            "2026-05-05T15:30:00+05:30",  # 10:00 UTC
            "2026-05-06T16:10:00+05:30",  # 10:40 UTC
            "2026-05-07T14:45:00+05:30",  # 09:15 UTC
            "2026-05-08T17:20:00+05:30",  # 11:50 UTC
        ]
        # Persona A's second account (Reddit posts around 09:00-11:00 UTC, same +05:30 offset)
        posts_persona_a2 = [
            "2026-05-11T14:50:00+05:30",
            "2026-05-12T15:10:00+05:30",
            "2026-05-13T16:40:00+05:30",
            "2026-05-14T17:05:00+05:30",
        ]
        # Colliding namesake Persona B (US West Coast UTC-07:00, active 21:00-23:00 UTC)
        commits_persona_b = [
            "2026-05-04T14:10:00-07:00",  # 21:10 UTC
            "2026-05-05T15:20:00-07:00",  # 22:20 UTC
            "2026-05-06T16:05:00-07:00",  # 23:05 UTC
            "2026-05-07T15:40:00-07:00",  # 22:40 UTC
        ]

        prof_a = build_temporal_profile(commits_persona_a)
        prof_b = build_temporal_profile(commits_persona_b)
        self.assertEqual(prof_a.inferred_timezone, "UTC+05:30")
        self.assertEqual(prof_b.inferred_timezone, "UTC-07:00")

        same_persona_corr = correlate_timestamps(commits_persona_a, posts_persona_a2)
        different_persona_corr = correlate_timestamps(commits_persona_a, commits_persona_b)

        self.assertGreater(same_persona_corr.composite_temporal_score, 0.85)
        self.assertLess(different_persona_corr.composite_temporal_score, 0.20)
        self.assertEqual(
            hourly_cosine_similarity(prof_a.hourly_histogram_utc, prof_b.hourly_histogram_utc),
            0.0,
        )

        # Verify local-timezone weekend_ratio: Friday 23:00-07:00 is Saturday in UTC+05:30!
        # 2026-05-08 is a Friday; 2026-05-08T20:00:00Z = 2026-05-09T01:30:00+05:30 (Saturday local)
        ist_weekend_prof = build_temporal_profile(
            [
                "2026-05-09T01:30:00+05:30",  # Saturday local, Friday UTC!
                "2026-05-09T02:00:00+05:30",  # Saturday local, Friday UTC!
            ]
        )
        self.assertEqual(ist_weekend_prof.weekend_ratio, 1.0)


if __name__ == "__main__":
    unittest.main()
