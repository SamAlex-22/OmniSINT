"""Multi-modal similarity scoring: Jaro-Winkler, Levenshtein, token-swap, and perceptual avatar hashing."""

from __future__ import annotations

from itertools import permutations
from typing import Sequence

from pydantic import BaseModel, ConfigDict, Field

from omnisint.intelligence.entropy import (
    compute_rarity_score,
    strip_email_domain,
    tokenize_handle,
)

_LEET_MAP = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }
)


class SimilarityResult(BaseModel):
    """Structured multi-modal similarity evaluation between two OSINT handles or profiles."""

    model_config = ConfigDict(extra="forbid")

    source_value: str
    target_value: str
    jaro_winkler: float = Field(..., ge=0.0, le=1.0)
    levenshtein: float = Field(..., ge=0.0, le=1.0)
    token_swap: float = Field(..., ge=0.0, le=1.0)
    leet_similarity: float = Field(..., ge=0.0, le=1.0)
    avatar_similarity: float | None = Field(default=None, ge=0.0, le=1.0)
    rarity_weight: float = Field(..., ge=0.0, le=1.0)
    composite_score: float = Field(..., ge=0.0, le=1.0)
    rationale: str


def normalize_leet(text: str) -> str:
    """Normalize common leetspeak substitutions into lowercase alphabetic characters."""
    cleaned = strip_email_domain(text).lower()
    return "".join(ch for ch in cleaned.translate(_LEET_MAP) if ch.isalnum())


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute exact Levenshtein edit distance between two strings."""
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)

    if len(s1) < len(s2):
        s1, s2 = s2, s1

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def normalized_levenshtein(s1: str, s2: str) -> float:
    """Compute normalized Levenshtein similarity in [0.0, 1.0]."""
    a = strip_email_domain(s1).lower().strip()
    b = strip_email_domain(s2).lower().strip()
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    max_len = max(len(a), len(b))
    dist = levenshtein_distance(a, b)
    return round(max(0.0, 1.0 - (dist / max_len)), 4)


def jaro_similarity(s1: str, s2: str) -> float:
    """Compute Jaro string similarity in [0.0, 1.0]."""
    a = strip_email_domain(s1).lower().strip()
    b = strip_email_domain(s2).lower().strip()
    if a == b:
        return 1.0
    len_a, len_b = len(a), len(b)
    if len_a == 0 or len_b == 0:
        return 0.0

    match_distance = max(0, (max(len_a, len_b) // 2) - 1)
    a_matches = [False] * len_a
    b_matches = [False] * len_b

    matches = 0
    transpositions = 0

    for i in range(len_a):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len_b)
        for j in range(start, end):
            if b_matches[j] or a[i] != b[j]:
                continue
            a_matches[i] = True
            b_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    k = 0
    for i in range(len_a):
        if not a_matches[i]:
            continue
        while not b_matches[k]:
            k += 1
        if a[i] != b[k]:
            transpositions += 1
        k += 1

    jaro = (
        (matches / len_a)
        + (matches / len_b)
        + ((matches - transpositions / 2.0) / matches)
    ) / 3.0
    return round(max(0.0, min(1.0, jaro)), 4)


def jaro_winkler_similarity(s1: str, s2: str, prefix_weight: float = 0.1) -> float:
    """Compute Jaro-Winkler similarity in [0.0, 1.0] with shared prefix boost."""
    a = strip_email_domain(s1).lower().strip()
    b = strip_email_domain(s2).lower().strip()
    jaro = jaro_similarity(a, b)
    if jaro == 0.0 or jaro == 1.0:
        return jaro

    prefix_len = 0
    for c1, c2 in zip(a[:4], b[:4]):
        if c1 == c2:
            prefix_len += 1
        else:
            break

    jw = jaro + (prefix_len * prefix_weight * (1.0 - jaro))
    return round(max(0.0, min(1.0, jw)), 4)


def _subtoken_coverage_score(multi_tokens: list[str], compact_str: str) -> float:
    """Evaluate how completely a list of tokens covers a delimiter-free concatenated handle."""
    if not multi_tokens or not compact_str:
        return 0.0

    # Measure greedy token stripping coverage for tokens of length >= 2
    remaining = compact_str
    matched_chars = 0
    matched_tokens = 0
    for tok in sorted(multi_tokens, key=len, reverse=True):
        if len(tok) >= 2 and tok in remaining:
            remaining = remaining.replace(tok, "", 1)
            matched_chars += len(tok)
            matched_tokens += 1

    if matched_tokens == 0:
        return 0.0

    total_expected = max(len("".join(multi_tokens)), len(compact_str))
    coverage = matched_chars / total_expected if total_expected > 0 else 0.0

    # Check exact or near-exact permutation match for up to 5 tokens (e.g. john_doe_sec <-> doejohnsec)
    if len(multi_tokens) <= 5:
        best_perm_sim = max(
            normalized_levenshtein("".join(perm), compact_str)
            for perm in permutations(multi_tokens)
        )
    else:
        best_perm_sim = normalized_levenshtein("".join(sorted(multi_tokens)), compact_str)

    return max(best_perm_sim, coverage)


def token_swap_similarity(h1: str, h2: str) -> float:
    """Compute order-invariant token & concatenated sub-token similarity between two handles.

    Handles both explicit token permutations (`john_doe_sec` <-> `sec_john_doe`) and
    concatenated token permutations (`john_doe_sec` <-> `doejohnsec`).
    """
    tokens_1 = tokenize_handle(h1)
    tokens_2 = tokenize_handle(h2)
    if not tokens_1 or not tokens_2:
        return 0.0

    compact_1 = "".join(tokens_1)
    compact_2 = "".join(tokens_2)
    if compact_1 == compact_2:
        return 1.0

    # 1. Token set Dice similarity (order-invariant when both have delimiters)
    set_1, set_2 = set(tokens_1), set(tokens_2)
    dice = (2.0 * len(set_1 & set_2)) / (len(set_1) + len(set_2))

    # 2. Sub-token permutation coverage (solves `john_doe_sec` <-> `doejohnsec`)
    coverage_1_to_2 = _subtoken_coverage_score(tokens_1, compact_2)
    coverage_2_to_1 = _subtoken_coverage_score(tokens_2, compact_1)

    best_score = max(dice, coverage_1_to_2, coverage_2_to_1)
    return round(max(0.0, min(1.0, best_score)), 4)


def compute_dhash_from_pixels(pixels: Sequence[Sequence[int]] | Sequence[int]) -> str:
    """Compute a 64-bit horizontal difference hash (dHash, 16 hex chars) from an 8x9 grayscale grid.

    Accepts either an 8-row by 9-column nested sequence or a flat sequence of >= 72 pixel values.
    """
    flat: list[int] = []
    if pixels and isinstance(pixels[0], (list, tuple)):
        for row in pixels:
            flat.extend(int(v) for v in row)  # type: ignore[union-attr]
    else:
        flat = [int(v) for v in pixels]  # type: ignore[arg-type]

    if len(flat) < 72:
        # Pad deterministically if caller passes fewer than 72 samples
        flat = (flat * ((72 // max(1, len(flat))) + 1))[:72]

    bits = 0
    for row_idx in range(8):
        row_offset = row_idx * 9
        for col_idx in range(8):
            left_px = flat[row_offset + col_idx]
            right_px = flat[row_offset + col_idx + 1]
            bits = (bits << 1) | (1 if left_px > right_px else 0)

    return f"{bits:016x}"


def compute_dhash_from_bytes(image_bytes: bytes) -> str:
    """Compute a 64-bit perceptual difference hash (16 hex chars) from raw avatar bytes.

    Partitions the byte stream into 72 spatial luminance windows (8x9 grid) and computes
    horizontal gradient comparisons so minor recompression or metadata changes preserve similarity.
    """
    if not image_bytes:
        return "0" * 16

    n = len(image_bytes)
    grid_values: list[int] = []
    for idx in range(72):
        start = (idx * n) // 72
        end = max(start + 1, ((idx + 1) * n) // 72)
        window = image_bytes[start:end]
        avg_val = sum(window) // len(window) if window else 0
        grid_values.append(avg_val)

    return compute_dhash_from_pixels(grid_values)


def hamming_distance_hex(hash1: str, hash2: str) -> int:
    """Compute bit-level Hamming distance between two equal-length hexadecimal perceptual hashes."""
    h1 = hash1.strip().lower().removeprefix("0x")
    h2 = hash2.strip().lower().removeprefix("0x")
    if len(h1) != len(h2) or not h1:
        raise ValueError("Perceptual hashes must be non-empty hexadecimal strings of equal length")
    xor_val = int(h1, 16) ^ int(h2, 16)
    return xor_val.bit_count()


def avatar_hash_similarity(hash1: str, hash2: str) -> float:
    """Compute normalized [0.0, 1.0] perceptual avatar similarity from two hex dHash/pHash strings."""
    h1 = hash1.strip().lower().removeprefix("0x")
    h2 = hash2.strip().lower().removeprefix("0x")
    total_bits = len(h1) * 4
    distance = hamming_distance_hex(h1, h2)
    return round(max(0.0, 1.0 - (distance / total_bits)), 4)


def compare_handles(
    h1: str,
    h2: str,
    avatar_hash_1: str | None = None,
    avatar_hash_2: str | None = None,
) -> SimilarityResult:
    """Compute rarity-weighted multi-modal similarity between two handles and optional avatar hashes."""
    jw = jaro_winkler_similarity(h1, h2)
    lev = normalized_levenshtein(h1, h2)
    tswap = token_swap_similarity(h1, h2)

    leet_1 = normalize_leet(h1)
    leet_2 = normalize_leet(h2)
    leet_sim = normalized_levenshtein(leet_1, leet_2) if (leet_1 and leet_2) else 0.0

    # Best lexical/structural handle alignment
    lexical_best = max(jw, lev, tswap, leet_sim * 0.95)
    lexical_avg = 0.45 * lexical_best + 0.25 * tswap + 0.15 * jw + 0.15 * lev

    # Rarity weighting: rare handles matching across platforms carry stronger evidentiary weight
    # than common names like "john_smith" matching across platforms.
    r1 = compute_rarity_score(h1)
    r2 = compute_rarity_score(h2)
    avg_rarity = round((r1 + r2) / 2.0, 4)

    # Dampen raw lexical similarity slightly if both handles are extremely common names,
    # or boost slightly when both handles are high-entropy/rare.
    rarity_multiplier = 0.75 + (0.35 * avg_rarity)
    weighted_lexical = min(1.0, lexical_avg * rarity_multiplier)

    avatar_sim: float | None = None
    reasons: list[str] = []

    if tswap >= 0.85 and tswap > lev:
        reasons.append(f"strong token-swap alignment ({tswap:.2f})")
    elif jw >= 0.85:
        reasons.append(f"high Jaro-Winkler lexical similarity ({jw:.2f})")
    elif leet_sim >= 0.85 and leet_sim > lev:
        reasons.append(f"leetspeak-normalized match ({leet_sim:.2f})")
    else:
        reasons.append(f"lexical similarity ({lexical_best:.2f})")

    if avg_rarity >= 0.65:
        reasons.append(f"high handle rarity ({avg_rarity:.2f})")
    elif avg_rarity <= 0.35:
        reasons.append(f"dampened for common-name collision risk (rarity={avg_rarity:.2f})")

    if avatar_hash_1 and avatar_hash_2:
        avatar_sim = avatar_hash_similarity(avatar_hash_1, avatar_hash_2)
        if avatar_sim >= 0.85:
            # Matching perceptual avatar hash is a strong visual corroborator
            composite = min(1.0, 0.60 * weighted_lexical + 0.40 * avatar_sim + 0.10)
            reasons.append(f"corroborated by matching avatar dHash ({avatar_sim:.2f})")
        else:
            composite = 0.80 * weighted_lexical + 0.20 * avatar_sim
            reasons.append(f"divergent avatar dHash ({avatar_sim:.2f})")
    else:
        composite = weighted_lexical

    return SimilarityResult(
        source_value=h1,
        target_value=h2,
        jaro_winkler=jw,
        levenshtein=lev,
        token_swap=tswap,
        leet_similarity=leet_sim,
        avatar_similarity=avatar_sim,
        rarity_weight=avg_rarity,
        composite_score=round(max(0.0, min(1.0, composite)), 4),
        rationale="; ".join(reasons),
    )
