"""Timezone inference and active-hour circadian fingerprinting from OSINT timestamps."""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Sequence

from pydantic import BaseModel, ConfigDict, Field


class TemporalProfile(BaseModel):
    """Circadian activity profile and inferred timezone derived from entity timestamps."""

    model_config = ConfigDict(extra="forbid")

    sample_count: int = Field(..., ge=0)
    hourly_histogram_utc: list[float] = Field(
        default_factory=lambda: [0.0] * 24,
        min_length=24,
        max_length=24,
    )
    inferred_utc_offset_hours: float = 0.0
    inferred_timezone: str = "UTC+00:00"
    peak_active_hours_utc: list[int] = Field(default_factory=list)
    quiet_hours_utc: list[int] = Field(default_factory=list)
    weekend_ratio: float = Field(default=0.0, ge=0.0, le=1.0)


class TemporalCorrelationResult(BaseModel):
    """Comparison result between two entities' temporal activity fingerprints."""

    model_config = ConfigDict(extra="forbid")

    cosine_similarity: float = Field(..., ge=0.0, le=1.0)
    smoothed_cosine_similarity: float = Field(..., ge=0.0, le=1.0)
    timezone_alignment_score: float = Field(..., ge=0.0, le=1.0)
    cadence_similarity: float = Field(..., ge=0.0, le=1.0)
    composite_temporal_score: float = Field(..., ge=0.0, le=1.0)
    inferred_timezone_a: str
    inferred_timezone_b: str
    rationale: str


def format_utc_offset(offset_hours: float) -> str:
    """Format a floating-point hour offset (e.g. 5.5 or -4.0) as 'UTC+05:30' or 'UTC-04:00'."""
    total_minutes = int(round(offset_hours * 60))
    sign = "+" if total_minutes >= 0 else "-"
    abs_minutes = abs(total_minutes)
    hours, minutes = divmod(abs_minutes, 60)
    return f"UTC{sign}{hours:02d}:{minutes:02d}"


def parse_timestamp(ts: datetime | str) -> tuple[datetime, float | None]:
    """Parse a datetime or ISO-8601 string into (utc_datetime, explicit_offset_hours_or_None)."""
    if isinstance(ts, str):
        cleaned = ts.strip()
        has_explicit_non_utc = (
            ("+" in cleaned[10:] or "-" in cleaned[10:])
            and not cleaned.endswith("Z")
            and not cleaned.endswith("+00:00")
            and not cleaned.endswith("-00:00")
        )
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        dt = datetime.fromisoformat(cleaned)
    else:
        dt = ts
        offset_td = dt.utcoffset() if dt.tzinfo is not None else None
        has_explicit_non_utc = offset_td is not None and offset_td.total_seconds() != 0

    if dt.tzinfo is None:
        dt_utc = dt.replace(tzinfo=timezone.utc)
        return dt_utc, None

    offset = dt.utcoffset()
    explicit_hours = (offset.total_seconds() / 3600.0) if (offset and has_explicit_non_utc) else None
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc, explicit_hours


def _infer_offset_from_sleep_window(hourly_hist: Sequence[float]) -> float:
    """Infer UTC offset in hours by locating the 7-hour minimum activity window (sleep trough).

    Assumes the human sleep trough is centered near 03:30 local time (00:00 - 07:00 local).
    Thus `local_hour = (utc_hour + offset) mod 24` -> `offset = 3.5 - sleep_center_utc`.
    """
    if sum(hourly_hist) == 0.0:
        return 0.0

    window_len = 7
    min_sum = float("inf")
    best_start = 0

    for start_hr in range(24):
        window_sum = sum(hourly_hist[(start_hr + k) % 24] for k in range(window_len))
        if window_sum < min_sum:
            min_sum = window_sum
            best_start = start_hr

    sleep_center_utc = (best_start + (window_len / 2.0)) % 24.0
    raw_offset = 3.5 - sleep_center_utc
    # Wrap into standard timezone range [-12.0, +12.0] rounded to nearest integer hour
    while raw_offset <= -12.0:
        raw_offset += 24.0
    while raw_offset > 12.0:
        raw_offset -= 24.0
    return float(round(raw_offset))


def build_temporal_profile(timestamps: Sequence[datetime | str]) -> TemporalProfile:
    """Construct a 24-hour UTC activity histogram and infer the operator's timezone."""
    if not timestamps:
        return TemporalProfile(sample_count=0)

    hour_counts = [0] * 24
    explicit_offsets: list[float] = []
    parsed_utc_times: list[datetime] = []

    for raw_ts in timestamps:
        dt_utc, explicit_offset = parse_timestamp(raw_ts)
        parsed_utc_times.append(dt_utc)
        hour_counts[dt_utc.hour] += 1
        if explicit_offset is not None:
            explicit_offsets.append(round(explicit_offset * 2) / 2.0)

    n = len(timestamps)
    histogram = [round(c / n, 4) for c in hour_counts]

    if explicit_offsets:
        # Use modal explicit timezone offset (e.g. from Git commit headers)
        most_common_offset = Counter(explicit_offsets).most_common(1)[0][0]
        inferred_offset = float(most_common_offset)
    else:
        inferred_offset = _infer_offset_from_sleep_window(histogram)

    offset_delta = timedelta(hours=inferred_offset)
    weekend_count = sum(1 for dt_utc in parsed_utc_times if (dt_utc + offset_delta).weekday() >= 5)

    ranked_hours = sorted(range(24), key=lambda h: hour_counts[h], reverse=True)
    peak_hours = [h for h in ranked_hours[:3] if hour_counts[h] > 0]
    quiet_hours = [h for h in range(24) if hour_counts[h] == 0][:8]

    return TemporalProfile(
        sample_count=n,
        hourly_histogram_utc=histogram,
        inferred_utc_offset_hours=inferred_offset,
        inferred_timezone=format_utc_offset(inferred_offset),
        peak_active_hours_utc=peak_hours,
        quiet_hours_utc=quiet_hours,
        weekend_ratio=round(weekend_count / n, 4),
    )


def hourly_cosine_similarity(hist_a: Sequence[float], hist_b: Sequence[float]) -> float:
    """Compute exact cosine similarity in [0.0, 1.0] between two 24-hour activity vectors."""
    if len(hist_a) != 24 or len(hist_b) != 24:
        raise ValueError("Activity histograms must contain exactly 24 hourly bins")

    dot = sum(a * b for a, b in zip(hist_a, hist_b))
    norm_a = math.sqrt(sum(a * a for a in hist_a))
    norm_b = math.sqrt(sum(b * b for b in hist_b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return round(max(0.0, min(1.0, dot / (norm_a * norm_b))), 4)


def _smooth_histogram(hist: Sequence[float]) -> list[float]:
    """Apply circular [0.25, 0.50, 0.25] 3-hour kernel smoothing to account for +/- 1h jitter."""
    return [
        0.25 * hist[(h - 1) % 24] + 0.50 * hist[h] + 0.25 * hist[(h + 1) % 24]
        for h in range(24)
    ]


def correlate_temporal_profiles(
    profile_a: TemporalProfile,
    profile_b: TemporalProfile,
) -> TemporalCorrelationResult:
    """Compare two TemporalProfiles across circadian rhythm, timezone offset, and weekend cadence."""
    if profile_a.sample_count == 0 or profile_b.sample_count == 0:
        return TemporalCorrelationResult(
            cosine_similarity=0.0,
            smoothed_cosine_similarity=0.0,
            timezone_alignment_score=0.0,
            cadence_similarity=0.0,
            composite_temporal_score=0.0,
            inferred_timezone_a=profile_a.inferred_timezone,
            inferred_timezone_b=profile_b.inferred_timezone,
            rationale="Insufficient timestamp samples for temporal correlation",
        )

    raw_cos = hourly_cosine_similarity(
        profile_a.hourly_histogram_utc,
        profile_b.hourly_histogram_utc,
    )
    smooth_cos = hourly_cosine_similarity(
        _smooth_histogram(profile_a.hourly_histogram_utc),
        _smooth_histogram(profile_b.hourly_histogram_utc),
    )

    # Circular timezone offset distance in hours (0 to 12 hours apart)
    raw_tz_diff = abs(profile_a.inferred_utc_offset_hours - profile_b.inferred_utc_offset_hours) % 24.0
    circular_tz_diff = min(raw_tz_diff, 24.0 - raw_tz_diff)
    tz_alignment = round(max(0.0, 1.0 - (circular_tz_diff / 12.0)), 4)

    # Weekday/weekend cadence similarity
    cadence_sim = round(1.0 - abs(profile_a.weekend_ratio - profile_b.weekend_ratio), 4)

    composite = round(
        max(
            0.0,
            min(
                1.0,
                0.45 * smooth_cos + 0.35 * tz_alignment + 0.10 * raw_cos + 0.10 * cadence_sim,
            ),
        ),
        4,
    )

    rationale = (
        f"Timezones {profile_a.inferred_timezone} vs {profile_b.inferred_timezone} "
        f"(alignment={tz_alignment:.2f}); smoothed circadian cosine={smooth_cos:.2f}"
    )

    return TemporalCorrelationResult(
        cosine_similarity=raw_cos,
        smoothed_cosine_similarity=smooth_cos,
        timezone_alignment_score=tz_alignment,
        cadence_similarity=cadence_sim,
        composite_temporal_score=composite,
        inferred_timezone_a=profile_a.inferred_timezone,
        inferred_timezone_b=profile_b.inferred_timezone,
        rationale=rationale,
    )


def correlate_timestamps(
    timestamps_a: Sequence[datetime | str],
    timestamps_b: Sequence[datetime | str],
) -> TemporalCorrelationResult:
    """Build temporal profiles from two timestamp sequences and compute their correlation."""
    prof_a = build_temporal_profile(timestamps_a)
    prof_b = build_temporal_profile(timestamps_b)
    return correlate_temporal_profiles(prof_a, prof_b)
