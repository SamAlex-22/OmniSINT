"""Shannon entropy, n-gram rarity, and handle collision probability scoring for OmniSINT."""

from __future__ import annotations

import math
import re
from collections import Counter

from pydantic import BaseModel, ConfigDict, Field

from omnisint.core.models import EntityNode

# High-collision given names, surnames, and generic handle words that appear across
# thousands of unrelated individuals on social and developer platforms.
COMMON_NAME_TOKENS: frozenset[str] = frozenset(
    {
        "john",
        "james",
        "robert",
        "michael",
        "william",
        "david",
        "richard",
        "joseph",
        "thomas",
        "charles",
        "christopher",
        "daniel",
        "matthew",
        "anthony",
        "mark",
        "donald",
        "steven",
        "paul",
        "andrew",
        "joshua",
        "kenneth",
        "kevin",
        "brian",
        "george",
        "timothy",
        "ronald",
        "edward",
        "jason",
        "jeffrey",
        "ryan",
        "jacob",
        "gary",
        "nicholas",
        "eric",
        "jonathan",
        "stephen",
        "larry",
        "justin",
        "scott",
        "brandon",
        "benjamin",
        "samuel",
        "gregory",
        "alexander",
        "alex",
        "patrick",
        "frank",
        "raymond",
        "jack",
        "dennis",
        "jerry",
        "mary",
        "patricia",
        "jennifer",
        "linda",
        "elizabeth",
        "barbara",
        "susan",
        "jessica",
        "sarah",
        "karen",
        "lisa",
        "nancy",
        "betty",
        "margaret",
        "sandra",
        "ashley",
        "kimberly",
        "emily",
        "donna",
        "michelle",
        "carol",
        "amanda",
        "melissa",
        "deborah",
        "stephanie",
        "rebecca",
        "sharon",
        "laura",
        "cynthia",
        "smith",
        "johnson",
        "williams",
        "brown",
        "jones",
        "garcia",
        "miller",
        "davis",
        "rodriguez",
        "martinez",
        "hernandez",
        "lopez",
        "gonzalez",
        "wilson",
        "anderson",
        "thomas",
        "taylor",
        "moore",
        "jackson",
        "martin",
        "lee",
        "perez",
        "thompson",
        "white",
        "harris",
        "sanchez",
        "clark",
        "ramirez",
        "lewis",
        "robinson",
        "walker",
        "young",
        "allen",
        "king",
        "wright",
        "scott",
        "torres",
        "nguyen",
        "hill",
        "flores",
        "green",
        "adams",
        "nelson",
        "baker",
        "hall",
        "rivera",
        "campbell",
        "mitchell",
        "carter",
        "roberts",
        "doe",
        "admin",
        "user",
        "test",
        "dev",
        "developer",
        "official",
        "real",
        "the",
        "info",
        "contact",
        "support",
        "hello",
        "mail",
        "web",
        "app",
        "tech",
        "pro",
        "gaming",
        "gamer",
        "crypto",
        # Multinational given names & surnames (South Asian, East Asian, Middle Eastern, Hispanic, European)
        "rahul",
        "sharma",
        "kumar",
        "singh",
        "patel",
        "priya",
        "vikram",
        "arjun",
        "wang",
        "wei",
        "li",
        "zhang",
        "chen",
        "liu",
        "yang",
        "huang",
        "zhao",
        "wu",
        "zhou",
        "mohammed",
        "muhammad",
        "ahmed",
        "ali",
        "hassan",
        "hussein",
        "fatima",
        "omar",
        "khalid",
        "ibrahim",
        "carlos",
        "jose",
        "luis",
        "jorge",
        "miguel",
        "maria",
        "ana",
        "sofia",
        "elena",
        "ivan",
        "dmitry",
        "sergey",
        "olga",
        "kim",
        "park",
        "choi",
        "jung",
        "tanaka",
        "sato",
        "suzuki",
        "mueller",
        "schmidt",
        "fischer",
        "dubois",
        "rossi",
        "silva",
        "santos",
    }
)

# High-frequency English character bigrams used to distinguish natural dictionary words
# from rare/synthetic handle sequences (e.g., "x7", "kr", "qz", "0x").
COMMON_ENGLISH_BIGRAMS: frozenset[str] = frozenset(
    {
        "th",
        "he",
        "in",
        "er",
        "an",
        "re",
        "on",
        "at",
        "en",
        "nd",
        "ti",
        "es",
        "or",
        "te",
        "of",
        "ed",
        "is",
        "it",
        "al",
        "ar",
        "st",
        "to",
        "nt",
        "ng",
        "se",
        "ha",
        "as",
        "ou",
        "io",
        "le",
        "ve",
        "co",
        "me",
        "de",
        "hi",
        "ri",
        "ro",
        "ic",
        "ne",
        "ea",
        "ra",
        "ce",
        "li",
        "ch",
        "ll",
        "be",
        "ma",
        "si",
        "om",
        "ur",
    }
)

_TOKEN_SPLIT_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\d|\W|$)|\d+")


class HandleEntropyMetrics(BaseModel):
    """Comprehensive information-theoretic and collision-risk metrics for an OSINT handle."""

    model_config = ConfigDict(extra="forbid")

    handle: str
    normalized_handle: str
    tokens: list[str]
    shannon_entropy: float = Field(..., ge=0.0)
    information_bits: float = Field(..., ge=0.0)
    rarity_score: float = Field(..., ge=0.0, le=1.0)
    collision_probability: float = Field(..., ge=0.0, le=1.0)
    is_high_collision_risk: bool


def strip_email_domain(value: str) -> str:
    """Return the local part if value is an email address, else the stripped string."""
    cleaned = value.strip()
    if "@" in cleaned and not cleaned.startswith("@"):
        return cleaned.split("@", 1)[0]
    return cleaned.lstrip("@")


def tokenize_handle(handle: str) -> list[str]:
    """Split a handle into lowercase alphanumeric sub-tokens across delimiters, camelCase, and digits."""
    local = strip_email_domain(handle)
    raw_tokens = _TOKEN_SPLIT_RE.findall(local)
    return [tok.lower() for tok in raw_tokens if tok]


def shannon_entropy(text: str) -> float:
    """Compute Shannon entropy H(X) in bits per character for a string."""
    cleaned = strip_email_domain(text)
    if not cleaned:
        return 0.0
    length = len(cleaned)
    counts = Counter(cleaned)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(max(0.0, entropy), 4)


def information_bits(text: str) -> float:
    """Compute total Shannon information content I(X) = |X| * H(X) in bits."""
    cleaned = strip_email_domain(text)
    if not cleaned:
        return 0.0
    return round(len(cleaned) * shannon_entropy(cleaned), 4)


def _unusual_bigram_ratio(alnum_lower: str) -> float:
    """Compute fraction of character bigrams that are NOT top-50 common English bigrams."""
    if len(alnum_lower) < 2:
        return 0.0
    bigrams = [alnum_lower[i : i + 2] for i in range(len(alnum_lower) - 1)]
    unusual = sum(1 for bg in bigrams if bg not in COMMON_ENGLISH_BIGRAMS)
    return unusual / len(bigrams)


def compute_rarity_score(handle: str) -> float:
    """Compute a normalized [0.0, 1.0] rarity score for a handle or username.

    Low scores (< 0.40) indicate common names/handles (`john_smith`, `alex`, `admin`) with
    high risk of false-positive namesake collisions across platforms.
    High scores (> 0.70) indicate distinctive handles (`x7_krypton_99`, `0x416c6578_sec`)
    that strongly anchor identity across platforms.
    """
    local = strip_email_domain(handle)
    if not local:
        return 0.0

    tokens = tokenize_handle(local)
    alnum_lower = "".join(ch.lower() for ch in local if ch.isalnum())
    if not alnum_lower:
        return 0.0

    # 1. Normalized Shannon entropy contribution (typical handles range 2.0 - 4.2 bits/char)
    h_bits = shannon_entropy(local)
    entropy_norm = min(1.0, h_bits / 4.0)

    # 2. Length / total information contribution (handles >= 12 chars carry more specificity)
    length_norm = min(1.0, len(alnum_lower) / 14.0)

    # 3. Unusual character bigram fraction (synthetic/rare stems vs common English stems)
    bigram_rarity = _unusual_bigram_ratio(alnum_lower)

    # 4. Character class diversity (alpha, digits, delimiters, mixed-case / hex patterns)
    has_lower = any(c.islower() for c in local)
    has_upper = any(c.isupper() for c in local)
    has_digit = any(c.isdigit() for c in local)
    has_delim = any(not c.isalnum() for c in local)
    class_count = sum([has_lower, has_upper, has_digit, has_delim])
    diversity_score = min(1.0, (class_count - 1) / 2.5) if class_count > 1 else 0.0

    # Base composite score before dictionary name penalties
    raw_score = (
        0.35 * entropy_norm
        + 0.25 * bigram_rarity
        + 0.20 * length_norm
        + 0.20 * diversity_score
    )

    # 5. Penalize common human names, surnames, and generic dictionary handle tokens
    if tokens:
        alpha_tokens = [t for t in tokens if t.isalpha()]
        digit_tokens = [t for t in tokens if t.isdigit()]

        if alpha_tokens:
            common_hits = sum(1 for t in alpha_tokens if t in COMMON_NAME_TOKENS)
            common_ratio = common_hits / len(alpha_tokens)
            # Heavy penalty when ALL alphabetic tokens are common names (e.g. "john_smith", "alex_jones")
            if common_ratio == 1.0:
                raw_score *= 0.38
            elif common_ratio >= 0.5:
                raw_score *= 0.68

        # Short numeric suffixes like "john123" or "alex99" are still common when paired with a common name
        if (
            len(alpha_tokens) == 1
            and alpha_tokens[0] in COMMON_NAME_TOKENS
            and len(digit_tokens) <= 1
        ):
            raw_score = min(raw_score, 0.35)

    # 6. Boost distinctive multi-token alphanumeric handles with rare stems (e.g. "x7_krypton_99")
    if has_digit and bigram_rarity >= 0.70 and len(alnum_lower) >= 8:
        extra_boost = 0.12 if all(t not in COMMON_NAME_TOKENS for t in tokens) else 0.04
        raw_score += extra_boost

    return round(max(0.01, min(0.99, raw_score)), 4)


def estimate_collision_probability(handle: str) -> float:
    """Estimate the probability [0.0, 1.0] that two accounts with this handle belong to different people."""
    return round(1.0 - compute_rarity_score(handle), 4)


def analyze_handle_entropy(handle: str) -> HandleEntropyMetrics:
    """Perform full entropy, token, rarity, and collision-risk analysis on a handle."""
    local = strip_email_domain(handle)
    tokens = tokenize_handle(local)
    normalized = "".join(tokens)
    h = shannon_entropy(local)
    info = information_bits(local)
    rarity = compute_rarity_score(local)
    collision = round(1.0 - rarity, 4)
    return HandleEntropyMetrics(
        handle=handle,
        normalized_handle=normalized,
        tokens=tokens,
        shannon_entropy=h,
        information_bits=info,
        rarity_score=rarity,
        collision_probability=collision,
        is_high_collision_risk=collision >= 0.60,
    )


def enrich_node_entropy(node: EntityNode) -> EntityNode:
    """Populate `entropy_score` and `rarity_score` on an EntityNode using its value."""
    metrics = analyze_handle_entropy(node.value)
    node.entropy_score = metrics.shannon_entropy
    node.rarity_score = metrics.rarity_score
    return node
