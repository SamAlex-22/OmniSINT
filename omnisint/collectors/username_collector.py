"""Passive multi-platform username discovery & profile/avatar collector (Sherlock-compatible)."""

from __future__ import annotations

import asyncio
from typing import Any, Sequence

from pydantic import BaseModel, ConfigDict

from omnisint.collectors.base import BaseCollector, CollectorConfig, HttpGetTransportCallable
from omnisint.config import OmniSINTSettings
from omnisint.core.custody import CustodyLedger
from omnisint.core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    EvidenceItem,
    RelationshipEdge,
    RelationType,
)
from omnisint.core.storage import CaseStorage
from omnisint.intelligence.entropy import analyze_handle_entropy
from omnisint.intelligence.similarity import compute_dhash_from_bytes


class PlatformSpec(BaseModel):
    """Definition of a passive platform check for UsernameCollector."""

    model_config = ConfigDict(extra="forbid")

    platform: str
    api_url_template: str
    profile_url_template: str
    response_kind: str = "json"


DEFAULT_PLATFORM_SPECS: tuple[PlatformSpec, ...] = (
    PlatformSpec(
        platform="GitHub",
        api_url_template="https://api.github.com/users/{handle}",
        profile_url_template="https://github.com/{handle}",
    ),
    PlatformSpec(
        platform="GitLab",
        api_url_template="https://gitlab.com/api/v4/users?username={handle}",
        profile_url_template="https://gitlab.com/{handle}",
    ),
    PlatformSpec(
        platform="Reddit",
        api_url_template="https://www.reddit.com/user/{handle}/about.json",
        profile_url_template="https://www.reddit.com/user/{handle}",
    ),
    PlatformSpec(
        platform="Keybase",
        api_url_template="https://keybase.io/_/api/1.0/user/lookup.json?usernames={handle}",
        profile_url_template="https://keybase.io/{handle}",
    ),
    PlatformSpec(
        platform="HackerNews",
        api_url_template="https://hacker-news.firebaseio.com/v0/user/{handle}.json",
        profile_url_template="https://news.ycombinator.com/user?id={handle}",
    ),
    PlatformSpec(
        platform="DevTo",
        api_url_template="https://dev.to/api/users/by_username?url={handle}",
        profile_url_template="https://dev.to/{handle}",
    ),
)


class UsernameCollector(BaseCollector):
    """Sherlock-style async multi-platform username discovery, metadata, and avatar dHash collector."""

    name = "username_collector"
    description = "Discovers social/developer profiles across public platforms and extracts bio, timestamps, and avatar dHash."
    supported_types = (EntityType.USERNAME, EntityType.PERSON)

    def __init__(
        self,
        platforms: Sequence[PlatformSpec] | None = None,
        config: CollectorConfig | None = None,
        settings: OmniSINTSettings | None = None,
        http_transport: HttpGetTransportCallable | None = None,
    ) -> None:
        super().__init__(config=config, settings=settings, http_transport=http_transport)
        self.platforms: list[PlatformSpec] = list(platforms or DEFAULT_PLATFORM_SPECS)

    @staticmethod
    def _parse_platform_payload(
        spec: PlatformSpec,
        handle: str,
        payload: str | dict[str, Any] | list[Any],
    ) -> dict[str, Any] | None:
        """Extract normalized profile metadata if the platform payload confirms an active account."""
        plat = spec.platform

        if plat == "GitHub" and isinstance(payload, dict) and payload.get("login"):
            return {
                "username": str(payload["login"]),
                "display_name": payload.get("name") or payload["login"],
                "bio": payload.get("bio") or "",
                "location": payload.get("location") or "",
                "avatar_url": payload.get("avatar_url") or "",
                "avatar_hash": payload.get("avatar_hash"),
                "avatar_bytes_seed": payload.get("avatar_bytes_hex"),
                "timestamps": payload.get("timestamps")
                or ([payload["created_at"]] if payload.get("created_at") else []),
                "url": payload.get("html_url") or spec.profile_url_template.format(handle=handle),
            }

        if plat == "GitLab" and isinstance(payload, list) and len(payload) > 0 and isinstance(payload[0], dict):
            user = payload[0]
            if user.get("username"):
                return {
                    "username": str(user["username"]),
                    "display_name": user.get("name") or user["username"],
                    "bio": user.get("bio") or "",
                    "location": user.get("location") or "",
                    "avatar_url": user.get("avatar_url") or "",
                    "avatar_hash": user.get("avatar_hash"),
                    "timestamps": user.get("timestamps")
                    or ([user["created_at"]] if user.get("created_at") else []),
                    "url": user.get("web_url") or spec.profile_url_template.format(handle=handle),
                }

        if plat == "Reddit" and isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, dict) and data.get("name"):
                sub = data.get("subreddit") or {}
                return {
                    "username": str(data["name"]),
                    "display_name": sub.get("title") or data["name"],
                    "bio": sub.get("public_description") or "",
                    "location": data.get("location") or "",
                    "avatar_url": data.get("icon_img") or "",
                    "avatar_hash": data.get("avatar_hash"),
                    "timestamps": data.get("timestamps") or [],
                    "url": spec.profile_url_template.format(handle=handle),
                }

        if plat == "Keybase" and isinstance(payload, dict):
            them = payload.get("them")
            if isinstance(them, list) and len(them) > 0 and isinstance(them[0], dict):
                user = them[0]
                basics = user.get("basics") or {}
                profile = user.get("profile") or {}
                pictures = user.get("pictures") or {}
                primary_pic = pictures.get("primary") or {}
                if basics.get("username"):
                    return {
                        "username": str(basics["username"]),
                        "display_name": profile.get("full_name") or basics["username"],
                        "bio": profile.get("bio") or "",
                        "location": profile.get("location") or "",
                        "avatar_url": primary_pic.get("url") or "",
                        "avatar_hash": user.get("avatar_hash"),
                        "timestamps": user.get("timestamps") or [],
                        "url": spec.profile_url_template.format(handle=handle),
                    }

        if plat == "HackerNews" and isinstance(payload, dict) and payload.get("id"):
            return {
                "username": str(payload["id"]),
                "display_name": str(payload["id"]),
                "bio": payload.get("about") or "",
                "location": payload.get("location") or "",
                "avatar_url": "",
                "avatar_hash": payload.get("avatar_hash"),
                "timestamps": payload.get("timestamps") or [],
                "url": spec.profile_url_template.format(handle=handle),
            }

        if plat == "DevTo" and isinstance(payload, dict) and payload.get("username"):
            return {
                "username": str(payload["username"]),
                "display_name": payload.get("name") or payload["username"],
                "bio": payload.get("summary") or "",
                "location": payload.get("location") or "",
                "avatar_url": payload.get("profile_image") or "",
                "avatar_hash": payload.get("avatar_hash"),
                "timestamps": payload.get("timestamps") or [],
                "url": spec.profile_url_template.format(handle=handle),
            }

        # Generic fallback for custom PlatformSpec entries
        if isinstance(payload, dict) and (payload.get("username") or payload.get("handle") or payload.get("login")):
            uname = str(payload.get("username") or payload.get("handle") or payload.get("login"))
            return {
                "username": uname,
                "display_name": payload.get("name") or uname,
                "bio": payload.get("bio") or "",
                "location": payload.get("location") or "",
                "avatar_url": payload.get("avatar_url") or "",
                "avatar_hash": payload.get("avatar_hash"),
                "timestamps": payload.get("timestamps") or [],
                "url": payload.get("url") or spec.profile_url_template.format(handle=handle),
            }

        return None

    async def collect(
        self,
        query: str,
        case_id: str,
        ledger: CustodyLedger | None = None,
        storage: CaseStorage | None = None,
    ) -> CollectorResult:
        """Enumerate public platforms for `query` username and emit profile/avatar nodes."""
        cleaned = query.strip().lstrip("@")
        active_ledger = ledger if ledger is not None else CustodyLedger(case_id=case_id)
        if not cleaned:
            return CollectorResult(
                collector_name=self.name,
                query=query,
                errors=["Username query cannot be empty"],
            )

        metrics = analyze_handle_entropy(cleaned)
        root_node = EntityNode(
            entity_type=EntityType.USERNAME,
            value=cleaned,
            entropy_score=metrics.shannon_entropy,
            rarity_score=metrics.rarity_score,
            confidence=0.90,
        )

        nodes: list[EntityNode] = [root_node]
        edges: list[RelationshipEdge] = []
        evidence_items: list[EvidenceItem] = []
        errors: list[str] = []

        semaphore = asyncio.Semaphore(self.config.max_concurrency)

        async def _probe_platform(spec: PlatformSpec) -> None:
            url = spec.api_url_template.format(handle=cleaned)
            async with semaphore:
                try:
                    status, payload, ev_item, _ = await self.fetch_with_custody(
                        url=url,
                        case_id=case_id,
                        ledger=active_ledger,
                        storage=storage,
                        notes=f"Username probe on {spec.platform} for '{cleaned}'",
                    )
                except Exception as exc:
                    errors.append(f"{spec.platform}: {type(exc).__name__}: {exc}")
                    return

                if status != 200 or ev_item is None:
                    return

                parsed = self._parse_platform_payload(spec, cleaned, payload)
                if parsed is None:
                    return

                evidence_items.append(ev_item)
                if ev_item.evidence_id not in root_node.evidence_ids:
                    root_node.evidence_ids.append(ev_item.evidence_id)

                av_hash = parsed.get("avatar_hash")
                if not av_hash and isinstance(parsed.get("avatar_bytes_seed"), str):
                    try:
                        av_hash = compute_dhash_from_bytes(bytes.fromhex(parsed["avatar_bytes_seed"]))
                    except ValueError:
                        av_hash = None

                profile_attrs: dict[str, Any] = {
                    "url": parsed["url"],
                    "display_name": parsed.get("display_name") or "",
                    "bio": parsed.get("bio") or "",
                }
                if parsed.get("location"):
                    profile_attrs["location"] = parsed["location"]
                if parsed.get("timestamps"):
                    profile_attrs["timestamps"] = list(parsed["timestamps"])
                if parsed.get("avatar_url"):
                    profile_attrs["avatar_url"] = parsed["avatar_url"]
                if av_hash:
                    profile_attrs["avatar_hash"] = av_hash

                prof_metrics = analyze_handle_entropy(parsed["username"])
                profile_node = EntityNode(
                    entity_type=EntityType.SOCIAL_PROFILE,
                    value=parsed["username"],
                    platform=spec.platform,
                    entropy_score=prof_metrics.shannon_entropy,
                    rarity_score=prof_metrics.rarity_score,
                    confidence=0.88,
                    attributes=profile_attrs,
                    evidence_ids=[ev_item.evidence_id],
                )
                nodes.append(profile_node)
                edges.append(
                    RelationshipEdge(
                        source_node_id=root_node.node_id,
                        target_node_id=profile_node.node_id,
                        relation_type=RelationType.HAS_PROFILE,
                        weight=0.90,
                        confidence=0.88,
                        rationale=f"Active {spec.platform} profile discovered for '{cleaned}'",
                        evidence_ids=[ev_item.evidence_id],
                    )
                )

                if av_hash:
                    avatar_node = EntityNode(
                        entity_type=EntityType.AVATAR_HASH,
                        value=str(av_hash),
                        confidence=0.92,
                        attributes={"source_platform": spec.platform, "avatar_url": parsed.get("avatar_url", "")},
                        evidence_ids=[ev_item.evidence_id],
                    )
                    nodes.append(avatar_node)
                    edges.append(
                        RelationshipEdge(
                            source_node_id=profile_node.node_id,
                            target_node_id=avatar_node.node_id,
                            relation_type=RelationType.HAS_AVATAR,
                            weight=0.92,
                            confidence=0.92,
                            rationale=f"Perceptual avatar dHash extracted from {spec.platform} profile",
                            evidence_ids=[ev_item.evidence_id],
                        )
                    )

        await asyncio.gather(*(_probe_platform(spec) for spec in self.platforms))

        return CollectorResult(
            collector_name=self.name,
            query=cleaned,
            nodes=nodes,
            edges=edges,
            evidence_items=evidence_items,
            errors=errors,
        )
