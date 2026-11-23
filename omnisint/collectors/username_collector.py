"""Passive multi-platform username discovery & profile/avatar collector (Sherlock-compatible)."""

from __future__ import annotations

import asyncio
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any, Sequence

from pydantic import BaseModel, ConfigDict, Field

from omnisint.collectors.base import BaseCollector, CollectorConfig, HttpGetTransportCallable
from omnisint.collectors.scrapling_collector import (
    extract_html_canonical_and_og_url,
    parse_public_profile_html,
)
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
    """Definition of a passive platform check for UsernameCollector (WhatsMyName & Sherlock compatible)."""

    model_config = ConfigDict(extra="forbid")

    platform: str
    api_url_template: str
    profile_url_template: str
    response_kind: str = "json"
    expected_status: int = 200
    existence_string: str | None = None
    missing_string: str | None = None
    missing_strings: list[str] = Field(default_factory=list)
    error_type: str = "status_code"
    error_url: str | None = None
    regex_check: str | None = None
    category: str = "social"


def _load_json_mapping(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Load a JSON dictionary from an in-memory dict, JSON string, or file path."""
    if isinstance(source, dict):
        return source
    if isinstance(source, Path):
        return dict(json.loads(source.read_text(encoding="utf-8")))
    raw_str = str(source).strip()
    if raw_str.startswith("{"):
        return dict(json.loads(raw_str))
    return dict(json.loads(Path(raw_str).read_text(encoding="utf-8")))


def _format_handle_url(template: str, handle: str) -> str:
    """Substitute `{handle}` or `{}` placeholders safely without failing on unrelated braces."""
    return template.replace("{}", "{handle}").replace("{handle}", handle)


def _url_matches_error_url(candidate_url: str, error_url: str) -> bool:
    """Return True when a redirect/canonical URL matches a Sherlock `errorUrl` indicator."""
    cand = candidate_url.strip()
    err = error_url.strip()
    if not cand or not err:
        return False
    cand_norm = cand.rstrip("/").lower()
    err_norm = err.rstrip("/").lower()
    if cand_norm == err_norm:
        return True
    parsed_err = urllib.parse.urlsplit(err_norm)
    if (parsed_err.path and parsed_err.path != "/") or parsed_err.query:
        return err_norm in cand_norm
    return False


def load_whatsmyname_specs(
    source: str | Path | dict[str, Any],
    max_sites: int | None = None,
) -> list[PlatformSpec]:
    """Load PlatformSpec entries from a WhatsMyName JSON file path, JSON string, or parsed dictionary."""
    if max_sites is not None and max_sites <= 0:
        return []
    data = _load_json_mapping(source)
    sites = data.get("sites") or []
    specs: list[PlatformSpec] = []
    for entry in sites:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        uri_check = str(entry.get("uri_check") or "").strip()
        uri_pretty = str(entry.get("uri_pretty") or uri_check).strip()
        if not name or not uri_check or "{account}" not in uri_check:
            continue
        m_str = entry.get("m_string")
        specs.append(
            PlatformSpec(
                platform=name,
                api_url_template=uri_check.replace("{account}", "{handle}"),
                profile_url_template=uri_pretty.replace("{account}", "{handle}"),
                response_kind="text",
                expected_status=int(entry.get("e_code", 200)),
                existence_string=entry.get("e_string"),
                missing_string=m_str,
                missing_strings=[m_str] if isinstance(m_str, str) and m_str else [],
                category=str(entry.get("cat") or "social"),
            )
        )
        if max_sites is not None and len(specs) >= max_sites:
            break
    return specs


def load_sherlock_specs(
    source: str | Path | dict[str, Any],
    max_sites: int | None = None,
) -> list[PlatformSpec]:
    """Load PlatformSpec entries from a Sherlock `data.json` path, JSON string, or parsed dictionary."""
    if max_sites is not None and max_sites <= 0:
        return []
    data = _load_json_mapping(source)
    specs: list[PlatformSpec] = []
    for name, entry in data.items():
        site_name = str(name).strip()
        if not site_name or site_name.startswith("$") or not isinstance(entry, dict):
            continue

        raw_profile_url = str(entry.get("url") or "").strip()
        raw_probe_url = str(entry.get("urlProbe") or raw_profile_url).strip()
        api_tmpl = raw_probe_url.replace("{}", "{handle}")
        profile_tmpl = (raw_profile_url or raw_probe_url).replace("{}", "{handle}")
        if "{handle}" not in api_tmpl:
            continue

        raw_err_type = entry.get("errorType")
        if isinstance(raw_err_type, list):
            err_type = str(raw_err_type[0] if raw_err_type else "status_code").strip().lower()
        else:
            err_type = str(raw_err_type or "status_code").strip().lower()
        if err_type not in {"status_code", "message", "response_url"}:
            err_type = "status_code"

        raw_msg = entry.get("errorMsg")
        missing_list: list[str] = []
        if isinstance(raw_msg, str) and raw_msg:
            missing_list = [raw_msg]
        elif isinstance(raw_msg, list):
            missing_list = [str(m) for m in raw_msg if isinstance(m, str) and m]

        raw_err_url = entry.get("errorUrl")
        err_url = (
            str(raw_err_url).strip().replace("{}", "{handle}")
            if isinstance(raw_err_url, str) and raw_err_url.strip()
            else None
        )
        raw_regex = entry.get("regexCheck")
        regex_check = str(raw_regex).strip() if isinstance(raw_regex, str) and raw_regex.strip() else None

        specs.append(
            PlatformSpec(
                platform=site_name,
                api_url_template=api_tmpl,
                profile_url_template=profile_tmpl,
                response_kind="text",
                expected_status=200,
                missing_string=missing_list[0] if missing_list else None,
                missing_strings=missing_list,
                error_type=err_type,
                error_url=err_url,
                regex_check=regex_check,
                category=str(entry.get("cat") or entry.get("category") or "social"),
            )
        )
        if max_sites is not None and len(specs) >= max_sites:
            break
    return specs


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
        fetch_avatars: bool = True,
        max_avatar_bytes: int = 2_000_000,
    ) -> None:
        super().__init__(config=config, settings=settings, http_transport=http_transport)
        self.platforms: list[PlatformSpec] = list(platforms or DEFAULT_PLATFORM_SPECS)
        self.fetch_avatars = fetch_avatars
        self.max_avatar_bytes = max_avatar_bytes

    @staticmethod
    def _parse_platform_payload(
        spec: PlatformSpec,
        handle: str,
        payload: str | dict[str, Any] | list[Any],
        headers: dict[str, str] | None = None,
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
                "url": payload.get("html_url") or _format_handle_url(spec.profile_url_template, handle),
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
                    "url": user.get("web_url") or _format_handle_url(spec.profile_url_template, handle),
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
                    "url": _format_handle_url(spec.profile_url_template, handle),
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
                        "url": _format_handle_url(spec.profile_url_template, handle),
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
                "url": _format_handle_url(spec.profile_url_template, handle),
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
                "url": _format_handle_url(spec.profile_url_template, handle),
            }

        # Sherlock & WhatsMyName text/HTML/response_url evaluation
        if isinstance(payload, str) or spec.response_kind == "text":
            text_payload = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
            missing_tokens = [
                tok
                for tok in (([spec.missing_string] if spec.missing_string else []) + list(spec.missing_strings))
                if tok
            ]
            if any(tok in text_payload for tok in missing_tokens):
                return None
            if spec.existence_string and spec.existence_string not in text_payload:
                return None

            if spec.error_type == "response_url" and spec.error_url:
                formatted_err = _format_handle_url(spec.error_url, handle)
                err_candidates = (
                    [formatted_err] if formatted_err == spec.error_url else [formatted_err, spec.error_url]
                )
                if headers:
                    lower_headers = {k.lower(): str(v) for k, v in headers.items()}
                    for hkey in ("location", "x-final-url", "content-location"):
                        hval = lower_headers.get(hkey, "").strip()
                        if hval and any(_url_matches_error_url(hval, ec) for ec in err_candidates):
                            return None
                if isinstance(payload, str):
                    if "<" in payload and ">" in payload:
                        canon_url, og_url = extract_html_canonical_and_og_url(payload)
                        for found_url in (canon_url, og_url):
                            if found_url and any(_url_matches_error_url(found_url, ec) for ec in err_candidates):
                                return None
                    lower_payload = payload.lower()
                    for ec in err_candidates:
                        parsed_ec = urllib.parse.urlsplit(ec.strip().lower())
                        if ((parsed_ec.path and parsed_ec.path != "/") or parsed_ec.query) and ec.lower() in lower_payload:
                            return None

            if isinstance(payload, dict) and (
                payload.get("username") or payload.get("handle") or payload.get("login")
            ):
                uname = str(payload.get("username") or payload.get("handle") or payload.get("login"))
                return {
                    "username": uname,
                    "display_name": payload.get("name") or uname,
                    "bio": payload.get("bio") or "",
                    "location": payload.get("location") or "",
                    "avatar_url": payload.get("avatar_url") or "",
                    "avatar_hash": payload.get("avatar_hash"),
                    "timestamps": payload.get("timestamps") or [],
                    "url": payload.get("url") or _format_handle_url(spec.profile_url_template, handle),
                }

            profile_url = _format_handle_url(spec.profile_url_template, handle)
            display_name = handle
            bio = ""
            avatar_url = ""
            location = ""
            if isinstance(payload, str) and "<" in payload and ">" in payload:
                meta = parse_public_profile_html(payload, profile_url)
                display_name = meta.display_name or handle
                bio = meta.bio
                avatar_url = meta.avatar_url
                location = meta.locations[0] if meta.locations else ""
            return {
                "username": handle,
                "display_name": display_name,
                "bio": bio,
                "location": location,
                "avatar_url": avatar_url,
                "avatar_hash": None,
                "timestamps": [],
                "url": profile_url,
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
                "url": payload.get("url") or _format_handle_url(spec.profile_url_template, handle),
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
            if spec.regex_check:
                try:
                    if not re.search(spec.regex_check, cleaned):
                        return
                except re.error:
                    return
            url = _format_handle_url(spec.api_url_template, cleaned)
            async with semaphore:
                try:
                    status, payload, ev_item, _, resp_headers = await self._fetch_with_custody_full(
                        url=url,
                        case_id=case_id,
                        ledger=active_ledger,
                        storage=storage,
                        notes=f"Username probe on {spec.platform} for '{cleaned}'",
                    )
                except Exception as exc:
                    errors.append(f"{spec.platform}: {type(exc).__name__}: {exc}")
                    return

                if status != spec.expected_status or ev_item is None:
                    return

                parsed = self._parse_platform_payload(
                    spec,
                    cleaned,
                    payload,
                    headers=resp_headers,
                )
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
                if not av_hash and self.fetch_avatars and parsed.get("avatar_url"):
                    raw_av_bytes = await self.fetch_bytes(
                        str(parsed["avatar_url"]),
                        max_bytes=self.max_avatar_bytes,
                    )
                    if raw_av_bytes:
                        av_hash = compute_dhash_from_bytes(raw_av_bytes)

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
