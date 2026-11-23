"""Labelled entity-resolution benchmark harness for calibrating & measuring KnowledgeGraphEngine accuracy."""

from __future__ import annotations

from collections import defaultdict
from itertools import combinations
from typing import Sequence

from pydantic import BaseModel, ConfigDict, Field

from omnisint.core.models import EntityNode, EntityType
from omnisint.intelligence.graph_engine import DisambiguationConfig, KnowledgeGraphEngine
from omnisint.intelligence.similarity import compute_dhash_from_pixels


class BenchmarkMetrics(BaseModel):
    """Pairwise precision/recall/F1 and Adjusted Rand Index (ARI) clustering evaluation metrics."""

    model_config = ConfigDict(extra="forbid")

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    pairwise_precision: float = Field(..., ge=0.0, le=1.0)
    pairwise_recall: float = Field(..., ge=0.0, le=1.0)
    pairwise_f1: float = Field(..., ge=0.0, le=1.0)
    adjusted_rand_index: float = Field(..., ge=-1.0, le=1.0)


class BenchmarkCase(BaseModel):
    """A single labelled multi-persona entity disambiguation test scenario."""

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str
    nodes: list[EntityNode]
    ground_truth_labels: dict[str, str]


class BenchmarkCaseResult(BaseModel):
    """Evaluation output for a single BenchmarkCase."""

    model_config = ConfigDict(extra="forbid")

    name: str
    predicted_cluster_count: int
    expected_cluster_count: int
    metrics: BenchmarkMetrics


def evaluate_clustering(
    predicted_clusters: Sequence[Sequence[str]],
    ground_truth_labels: dict[str, str],
) -> BenchmarkMetrics:
    """Compute exact pairwise Precision, Recall, F1, and Adjusted Rand Index (ARI) in pure Python."""
    eval_ids = sorted(ground_truth_labels.keys())
    if len(eval_ids) < 2:
        return BenchmarkMetrics(
            pairwise_precision=1.0,
            pairwise_recall=1.0,
            pairwise_f1=1.0,
            adjusted_rand_index=1.0,
        )

    pred_label: dict[str, str] = {}
    for idx, cluster in enumerate(predicted_clusters):
        cid = f"pred-{idx}"
        for nid in cluster:
            if nid in ground_truth_labels:
                pred_label[nid] = cid
    for nid in eval_ids:
        pred_label.setdefault(nid, f"singleton-{nid}")

    tp = fp = fn = tn = 0
    for a, b in combinations(eval_ids, 2):
        same_pred = pred_label[a] == pred_label[b]
        same_true = ground_truth_labels[a] == ground_truth_labels[b]
        if same_pred and same_true:
            tp += 1
        elif same_pred and not same_true:
            fp += 1
        elif not same_pred and same_true:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fn == 0 else 0.0)
    recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if fp == 0 else 0.0)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    # Hubert-Arabie Adjusted Rand Index
    n = len(eval_ids)
    total_pairs = n * (n - 1) / 2.0
    sum_pred_pairs = sum(
        c * (c - 1) / 2.0
        for c in _count_groups(pred_label[nid] for nid in eval_ids).values()
    )
    sum_true_pairs = sum(
        c * (c - 1) / 2.0
        for c in _count_groups(ground_truth_labels[nid] for nid in eval_ids).values()
    )
    expected_index = (sum_pred_pairs * sum_true_pairs) / total_pairs if total_pairs > 0 else 0.0
    max_index = 0.5 * (sum_pred_pairs + sum_true_pairs)
    denom = max_index - expected_index
    if abs(denom) < 1e-12:
        ari = 1.0 if (fp == 0 and fn == 0) else 0.0
    else:
        ari = (tp - expected_index) / denom

    return BenchmarkMetrics(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        pairwise_precision=round(precision, 4),
        pairwise_recall=round(recall, 4),
        pairwise_f1=round(f1, 4),
        adjusted_rand_index=round(max(-1.0, min(1.0, ari)), 4),
    )


def _count_groups(labels: Sequence[str] | Any) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for lbl in labels:
        counts[lbl] += 1
    return counts


def default_benchmark_cases() -> list[BenchmarkCase]:
    """Return a multi-scenario labelled benchmark suite covering edge cases and multinational namesakes."""
    grid_a = [[(r * 25 + c * 12) % 255 for c in range(9)] for r in range(8)]
    dhash_a = compute_dhash_from_pixels(grid_a)
    grid_b = [[(r * 5 + c * 40) % 255 for c in range(9)] for r in range(8)]
    dhash_b = compute_dhash_from_pixels(grid_b)

    return [
        BenchmarkCase(
            name="rare_tokenswap_and_timezone_split",
            description="Rare token-swapped handles merged; Seattle namesake separated by timezone & location.",
            nodes=[
                EntityNode(
                    node_id="r1",
                    entity_type=EntityType.SOCIAL_PROFILE,
                    value="krypton_sec_x7",
                    platform="GitHub",
                    attributes={
                        "location": "Bengaluru, India",
                        "avatar_hash": dhash_a,
                        "timestamps": ["2026-05-04T14:15:00+05:30", "2026-05-05T15:30:00+05:30"],
                    },
                ),
                EntityNode(
                    node_id="r2",
                    entity_type=EntityType.SOCIAL_PROFILE,
                    value="x7kryptonsec",
                    platform="Twitter",
                    attributes={
                        "location": "Bangalore",
                        "avatar_hash": dhash_a,
                        "timestamps": ["2026-05-06T14:50:00+05:30", "2026-05-07T16:10:00+05:30"],
                    },
                ),
                EntityNode(
                    node_id="r3",
                    entity_type=EntityType.SOCIAL_PROFILE,
                    value="krypton_sec_x7",
                    platform="GitLab",
                    attributes={
                        "location": "Seattle, USA",
                        "avatar_hash": dhash_b,
                        "timestamps": ["2026-05-04T14:10:00-07:00", "2026-05-05T15:20:00-07:00"],
                    },
                ),
            ],
            ground_truth_labels={"r1": "p_in", "r2": "p_in", "r3": "p_us"},
        ),
        BenchmarkCase(
            name="multinational_namesake_collision_guard",
            description="Uncorroborated common names (rahul_sharma, wang_wei, mohammed_ali, john_smith) must not merge.",
            nodes=[
                EntityNode(node_id="m1", entity_type=EntityType.SOCIAL_PROFILE, value="rahul_sharma", platform="GitHub"),
                EntityNode(node_id="m2", entity_type=EntityType.SOCIAL_PROFILE, value="rahul_sharma", platform="Reddit"),
                EntityNode(node_id="m3", entity_type=EntityType.SOCIAL_PROFILE, value="wang_wei", platform="GitHub"),
                EntityNode(node_id="m4", entity_type=EntityType.SOCIAL_PROFILE, value="wang_wei", platform="GitLab"),
                EntityNode(node_id="m5", entity_type=EntityType.SOCIAL_PROFILE, value="mohammed_ali", platform="Keybase"),
                EntityNode(node_id="m6", entity_type=EntityType.SOCIAL_PROFILE, value="mohammed_ali", platform="DevTo"),
            ],
            ground_truth_labels={
                "m1": "p1",
                "m2": "p2",
                "m3": "p3",
                "m4": "p4",
                "m5": "p5",
                "m6": "p6",
            },
        ),
        BenchmarkCase(
            name="location_alias_and_shared_email_corroboration",
            description="Traveller/alias spellings (NYC vs New York) corroborated by shared email & avatar merge cleanly.",
            nodes=[
                EntityNode(
                    node_id="t1",
                    entity_type=EntityType.SOCIAL_PROFILE,
                    value="alex_dev",
                    platform="GitHub",
                    attributes={"location": "NYC", "email": "alex@ny-sec.org", "avatar_hash": dhash_a},
                ),
                EntityNode(
                    node_id="t2",
                    entity_type=EntityType.SOCIAL_PROFILE,
                    value="alex_dev",
                    platform="Twitter",
                    attributes={"location": "New York, USA", "email": "alex@ny-sec.org", "avatar_hash": dhash_a},
                ),
                EntityNode(
                    node_id="t3",
                    entity_type=EntityType.SOCIAL_PROFILE,
                    value="alex_dev",
                    platform="Reddit",
                    attributes={"location": "London, UK", "avatar_hash": dhash_b},
                ),
            ],
            ground_truth_labels={"t1": "p_nyc", "t2": "p_nyc", "t3": "p_uk"},
        ),
    ]


def run_disambiguation_benchmark(
    config: DisambiguationConfig | None = None,
    cases: Sequence[BenchmarkCase] | None = None,
) -> tuple[BenchmarkMetrics, list[BenchmarkCaseResult]]:
    """Run KnowledgeGraphEngine across labelled benchmark cases and compute aggregate accuracy metrics."""
    bench_cases = list(cases or default_benchmark_cases())
    results: list[BenchmarkCaseResult] = []
    tot_tp = tot_fp = tot_fn = tot_tn = 0
    ari_values: list[float] = []

    for bcase in bench_cases:
        engine = KnowledgeGraphEngine(config=config)
        engine.ingest_nodes_and_edges(bcase.nodes)
        report = engine.resolve_personas()
        predicted_clusters = [p.node_ids for p in report.personas]
        metrics = evaluate_clustering(predicted_clusters, bcase.ground_truth_labels)

        tot_tp += metrics.true_positives
        tot_fp += metrics.false_positives
        tot_fn += metrics.false_negatives
        tot_tn += metrics.true_negatives
        ari_values.append(metrics.adjusted_rand_index)

        results.append(
            BenchmarkCaseResult(
                name=bcase.name,
                predicted_cluster_count=len(predicted_clusters),
                expected_cluster_count=len(set(bcase.ground_truth_labels.values())),
                metrics=metrics,
            )
        )

    precision = tot_tp / (tot_tp + tot_fp) if (tot_tp + tot_fp) > 0 else 1.0
    recall = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    avg_ari = sum(ari_values) / len(ari_values) if ari_values else 1.0

    aggregate = BenchmarkMetrics(
        true_positives=tot_tp,
        false_positives=tot_fp,
        false_negatives=tot_fn,
        true_negatives=tot_tn,
        pairwise_precision=round(precision, 4),
        pairwise_recall=round(recall, 4),
        pairwise_f1=round(f1, 4),
        adjusted_rand_index=round(avg_ari, 4),
    )
    return aggregate, results
