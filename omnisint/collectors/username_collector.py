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
from omnisint.intelligence.entropy import COMMON_NAME_TOKENS, analyze_handle_entropy
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


NAME_SHORT_FORMS: dict[str, str] = {
    "samuel": "sam",
    "alexander": "alex",
    "william": "will",
    "robert": "bob",
    "michael": "mike",
    "christopher": "chris",
    "matthew": "matt",
    "joseph": "joe",
    "daniel": "dan",
    "andrew": "andy",
    "benjamin": "ben",
    "nicholas": "nick",
    "anthony": "tony",
    "joshua": "josh",
    "david": "dave",
    "thomas": "tom",
    "james": "jim",
    "richard": "rick",
    "steven": "steve",
    "stephen": "steve",
    "edward": "ed",
    "patrick": "pat",
    "timothy": "tim",
    "jonathan": "jon",
    "elizabeth": "liz",
    "jennifer": "jen",
    "katherine": "kate",
}

_KNOWN_NAME_TOKENS_SET: frozenset[str] = frozenset(
    t.lower()
    for t in (
        set(COMMON_NAME_TOKENS)
        | set(NAME_SHORT_FORMS.keys())
        | set(NAME_SHORT_FORMS.values())
    )
    if t.isalpha()
)

_KNOWN_SEGMENT_NAMES: tuple[str, ...] = tuple(
    sorted((t for t in _KNOWN_NAME_TOKENS_SET if len(t) >= 3), key=len, reverse=True)
)

_FAST_EXTENDED_VARIANT_PLATFORMS: frozenset[str] = frozenset(
    {
        "GitHub",
        "GitLab",
        "Reddit",
        "Medium",
        "Linktree",
        "HuggingFace",
        "Kaggle",
        "LeetCode",
        "TryHackMe",
        "DockerHub",
    }
)


def _segment_concatenated_word(word: str) -> list[str] | None:
    """Segment an unbroken lowercase alphabetic name string (e.g. 'samuelalexanderv') via dictionary DFS."""
    n = len(word)
    if n < 6 or not word.isalpha():
        return None
    memo: dict[int, list[str] | None] = {}

    def _dfs(pos: int) -> list[str] | None:
        if pos == n:
            return []
        if pos in memo:
            return memo[pos]
        # Optional single-character trailing initial (e.g. "v") once >= 1 full token precedes it
        if n - pos == 1 and pos > 0 and word[pos].isalpha():
            memo[pos] = [word[pos]]
            return memo[pos]
        for token in _KNOWN_SEGMENT_NAMES:
            if word.startswith(token, pos):
                rest = _dfs(pos + len(token))
                if rest is not None:
                    memo[pos] = [token] + rest
                    return memo[pos]
        memo[pos] = None
        return None

    res = _dfs(0)
    if res is None:
        return None
    long_known = [tok for tok in res if len(tok) >= 3 and tok in _KNOWN_NAME_TOKENS_SET]
    if len(long_known) >= 2:
        return res
    return None


def split_concatenated_name_tokens(raw: str) -> list[str]:
    """Split spaced, delimited, camelCase, or concatenated person names into lowercase tokens."""
    cleaned = raw.strip().lstrip("@")
    if not cleaned:
        return []

    if any(sep in cleaned for sep in (" ", "\t", "_", "-", ".")):
        parts = [re.sub(r"[^a-z0-9]", "", tok.lower()) for tok in re.split(r"[\s_.-]+", cleaned)]
        return [tok for tok in parts if tok]

    camel_parts = re.findall(r"[A-Z][a-z]+|[A-Z]+(?=[A-Z][a-z]|\d|$)|[a-z]+|\d+", cleaned)
    if len(camel_parts) >= 2 and cleaned != cleaned.lower() and cleaned != cleaned.upper():
        return [p.lower() for p in camel_parts if p]

    if cleaned.isalpha() and len(cleaned) >= 6:
        segmented = _segment_concatenated_word(cleaned.lower())
        if segmented:
            return segmented

    alnum = re.sub(r"[^a-z0-9]", "", cleaned.lower())
    return [alnum] if alnum else []


def is_human_name_query(query: str) -> bool:
    """Return True when `query` represents a multi-word or concatenated human full name."""
    cleaned = query.strip()
    if not cleaned or cleaned.startswith("@") or "@" in cleaned:
        return False
    lower = cleaned.lower()
    if lower.startswith(("http://", "https://")):
        return False
    if " " in cleaned or "\t" in cleaned:
        return True
    if any(ch in cleaned for ch in ("_", "-", ".")) or any(ch.isdigit() for ch in cleaned):
        return False
    return cleaned.isalpha() and len(split_concatenated_name_tokens(cleaned)) >= 2


def derive_search_name_variants(query: str) -> list[str]:
    """Build natural human-name search variants (spaced, without trailing initial, and short forms)."""
    cleaned = query.strip().lstrip("@")
    if not cleaned:
        return []
    if not is_human_name_query(cleaned) and " " not in cleaned and "\t" not in cleaned:
        return [cleaned]

    tokens = split_concatenated_name_tokens(cleaned)
    if len(tokens) <= 1:
        return [cleaned]

    full_spaced = " ".join(tok.title() for tok in tokens)
    core_tokens = [tok for tok in tokens if len(tok) > 1][:2]
    variants = [full_spaced]
    if core_tokens and core_tokens != tokens:
        variants.append(" ".join(tok.title() for tok in core_tokens))
    short_tokens = [NAME_SHORT_FORMS.get(tok, tok) for tok in (core_tokens or tokens)]
    if short_tokens != (core_tokens or tokens):
        variants.append(" ".join(tok.title() for tok in short_tokens))

    seen: set[str] = set()
    unique: list[str] = []
    for variant in variants:
        key = variant.strip().lower()
        if variant.strip() and key not in seen:
            seen.add(key)
            unique.append(variant.strip())
    return unique or [cleaned]


def derive_handle_candidates(query: str) -> list[str]:
    """Generate separated, initial-free, and nickname handle candidates for human names."""
    cleaned = query.strip().lstrip("@")
    if not cleaned:
        return []

    has_space = " " in cleaned or "\t" in cleaned
    if not has_space and (
        any(sep in cleaned for sep in ("_", "-", "."))
        or any(ch.isdigit() for ch in cleaned)
    ):
        return [cleaned]

    tokens = split_concatenated_name_tokens(cleaned)
    if len(tokens) < 2:
        return [cleaned]

    candidates: list[str] = []
    if not has_space:
        candidates.append(cleaned)

    candidates.extend(
        [
            "".join(tokens),
            "_".join(tokens),
            "-".join(tokens),
            ".".join(tokens),
        ]
    )

    core_tokens = [tok for tok in tokens if len(tok) > 1][:2]
    if core_tokens and core_tokens != tokens:
        candidates.extend(
            [
                "".join(core_tokens),
                "-".join(core_tokens),
                "_".join(core_tokens),
                ".".join(core_tokens),
            ]
        )

    short_tokens = [NAME_SHORT_FORMS.get(tok, tok) for tok in (core_tokens or tokens)]
    if short_tokens != (core_tokens or tokens):
        candidates.extend(
            [
                "".join(short_tokens),
                "-".join(short_tokens),
                "_".join(short_tokens),
            ]
        )

    seen: set[str] = set()
    unique: list[str] = []
    for cand in candidates:
        key = cand.strip().lower()
        if cand.strip() and key not in seen:
            seen.add(key)
            unique.append(cand.strip())
            if len(unique) >= 11:
                break
    return unique or [cleaned]


DEFAULT_PLATFORM_SPECS: tuple[PlatformSpec, ...] = (
    # JSON API platforms (richest metadata: bio, location, timestamps, avatar URL)
    PlatformSpec(
        platform="GitHub",
        api_url_template="https://api.github.com/users/{handle}",
        profile_url_template="https://github.com/{handle}",
        category="coding",
    ),
    PlatformSpec(
        platform="GitLab",
        api_url_template="https://gitlab.com/api/v4/users?username={handle}",
        profile_url_template="https://gitlab.com/{handle}",
        category="coding",
    ),
    PlatformSpec(
        platform="Reddit",
        api_url_template="https://www.reddit.com/user/{handle}/about.json",
        profile_url_template="https://www.reddit.com/user/{handle}",
        category="social",
    ),
    PlatformSpec(
        platform="Keybase",
        api_url_template="https://keybase.io/_/api/1.0/user/lookup.json?usernames={handle}",
        profile_url_template="https://keybase.io/{handle}",
        category="identity",
    ),
    PlatformSpec(
        platform="HackerNews",
        api_url_template="https://hacker-news.firebaseio.com/v0/user/{handle}.json",
        profile_url_template="https://news.ycombinator.com/user?id={handle}",
        category="coding",
    ),
    PlatformSpec(
        platform="DevTo",
        api_url_template="https://dev.to/api/users/by_username?url={handle}",
        profile_url_template="https://dev.to/{handle}",
        category="coding",
    ),
    PlatformSpec(
        platform="DockerHub",
        api_url_template="https://hub.docker.com/v2/users/{handle}/",
        profile_url_template="https://hub.docker.com/u/{handle}",
        category="coding",
    ),
    PlatformSpec(
        platform="ChessCom",
        api_url_template="https://api.chess.com/pub/player/{handle}",
        profile_url_template="https://www.chess.com/member/{handle}",
        category="gaming",
    ),
    PlatformSpec(
        platform="Gravatar",
        api_url_template="https://en.gravatar.com/{handle}.json",
        profile_url_template="https://en.gravatar.com/{handle}",
        category="identity",
    ),
    # High-signal text/JSON/HTML WhatsMyName & Sherlock presets (guarded by existence_string + missing_string)
    PlatformSpec(
        platform="Codeforces",
        api_url_template="https://codeforces.com/api/user.info?handles={handle}",
        profile_url_template="https://codeforces.com/profile/{handle}",
        response_kind="text",
        existence_string='"status":"OK"',
        missing_string='"status":"FAILED"',
        category="coding",
    ),
    PlatformSpec(
        platform="TryHackMe",
        api_url_template="https://tryhackme.com/api/v2/public-profile?username={handle}",
        profile_url_template="https://tryhackme.com/p/{handle}",
        response_kind="text",
        existence_string='"status":"success"',
        missing_string='"status":"error"',
        category="security",
    ),
    PlatformSpec(
        platform="HuggingFace",
        api_url_template="https://huggingface.co/api/users/{handle}/overview",
        profile_url_template="https://huggingface.co/{handle}",
        response_kind="text",
        existence_string='"user"',
        missing_string="User not found",
        category="coding",
    ),
    PlatformSpec(
        platform="Bitbucket",
        api_url_template="https://api.bitbucket.org/2.0/workspaces/{handle}",
        profile_url_template="https://bitbucket.org/{handle}/",
        response_kind="text",
        existence_string='"uuid"',
        missing_string='"type": "error"',
        category="coding",
    ),
    PlatformSpec(
        platform="Medium",
        api_url_template="https://medium.com/@{handle}",
        profile_url_template="https://medium.com/@{handle}",
        response_kind="text",
        existence_string="og:type",
        missing_string="PAGE NOT FOUND",
        missing_strings=["PAGE NOT FOUND", "404"],
        category="writing",
    ),
    PlatformSpec(
        platform="Linktree",
        api_url_template="https://linktr.ee/{handle}",
        profile_url_template="https://linktr.ee/{handle}",
        response_kind="text",
        existence_string='"username"',
        missing_string="The page you're looking for doesn't exist",
        missing_strings=[
            "The page you're looking for doesn't exist",
            "The page you’re looking for doesn’t exist",
        ],
        category="social",
    ),
    PlatformSpec(
        platform="Kaggle",
        api_url_template="https://www.kaggle.com/{handle}",
        profile_url_template="https://www.kaggle.com/{handle}",
        response_kind="text",
        existence_string="og:title",
        missing_string="We couldn't find that page",
        category="coding",
    ),
    PlatformSpec(
        platform="LeetCode",
        api_url_template="https://leetcode.com/u/{handle}/",
        profile_url_template="https://leetcode.com/u/{handle}/",
        response_kind="text",
        existence_string="og:title",
        missing_string="Page Not Found",
        category="coding",
    ),
    PlatformSpec(
        platform="AboutMe",
        api_url_template="https://about.me/{handle}",
        profile_url_template="https://about.me/{handle}",
        response_kind="text",
        existence_string="og:title",
        missing_string="Whoops!",
        category="identity",
    ),
    PlatformSpec(
        platform="Vimeo",
        api_url_template="https://vimeo.com/{handle}",
        profile_url_template="https://vimeo.com/{handle}",
        response_kind="text",
        existence_string="og:title",
        missing_string="Sorry, we couldn’t find that page",
        category="video",
    ),
    PlatformSpec(
        platform="SoundCloud",
        api_url_template="https://soundcloud.com/{handle}",
        profile_url_template="https://soundcloud.com/{handle}",
        response_kind="text",
        existence_string="og:title",
        missing_string="We can't find that user",
        category="audio",
    ),
    PlatformSpec(
        platform="Pinterest",
        api_url_template="https://www.pinterest.com/{handle}/",
        profile_url_template="https://www.pinterest.com/{handle}/",
        response_kind="text",
        existence_string="og:title",
        missing_string="User not found",
        category="social",
    ),
    PlatformSpec(
        platform="Steam",
        api_url_template="https://steamcommunity.com/id/{handle}",
        profile_url_template="https://steamcommunity.com/id/{handle}",
        response_kind="text",
        existence_string="actual_persona_name",
        missing_string="The specified profile could not be found",
        category="gaming",
    ),
    PlatformSpec(
        platform="Telegram",
        api_url_template="https://t.me/{handle}",
        profile_url_template="https://t.me/{handle}",
        response_kind="text",
        existence_string="tgme_page_title",
        missing_string="If you have <strong>Telegram</strong>, you can contact",
        category="messaging",
    ),
    PlatformSpec(
        platform="YouTube",
        api_url_template="https://www.youtube.com/@{handle}",
        profile_url_template="https://www.youtube.com/@{handle}",
        response_kind="text",
        existence_string="og:title",
        missing_string="404 Not Found",
        category="video",
    ),
    PlatformSpec(
        platform="NPM",
        api_url_template="https://www.npmjs.com/~{handle}",
        profile_url_template="https://www.npmjs.com/~{handle}",
        response_kind="text",
        existence_string="og:title",
        missing_string="Cannot find user",
        category="coding",
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

        if plat == "DockerHub" and isinstance(payload, dict) and payload.get("username"):
            uname = str(payload["username"])
            return {
                "username": uname,
                "display_name": payload.get("full_name") or uname,
                "bio": payload.get("company") or "",
                "location": payload.get("location") or "",
                "avatar_url": payload.get("gravatar_url") or "",
                "avatar_hash": payload.get("avatar_hash"),
                "timestamps": [payload["date_joined"]] if payload.get("date_joined") else [],
                "url": _format_handle_url(spec.profile_url_template, uname),
            }

        if plat == "ChessCom" and isinstance(payload, dict) and payload.get("username"):
            uname = str(payload["username"])
            return {
                "username": uname,
                "display_name": payload.get("name") or uname,
                "bio": payload.get("title") or "",
                "location": payload.get("location") or "",
                "avatar_url": payload.get("avatar") or "",
                "avatar_hash": payload.get("avatar_hash"),
                "timestamps": [],
                "url": payload.get("url") or _format_handle_url(spec.profile_url_template, uname),
            }

        if plat == "Gravatar" and isinstance(payload, dict) and isinstance(payload.get("entry"), list) and payload["entry"]:
            entry = payload["entry"][0]
            if isinstance(entry, dict) and (entry.get("preferredUsername") or entry.get("displayName") or entry.get("id")):
                uname = str(entry.get("preferredUsername") or handle)
                return {
                    "username": uname,
                    "display_name": entry.get("displayName") or uname,
                    "bio": entry.get("aboutMe") or "",
                    "location": entry.get("currentLocation") or "",
                    "avatar_url": entry.get("thumbnailUrl") or "",
                    "avatar_hash": None,
                    "timestamps": [],
                    "url": entry.get("profileUrl") or _format_handle_url(spec.profile_url_template, handle),
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

        is_person = is_human_name_query(cleaned) or " " in cleaned or "\t" in cleaned
        metrics = analyze_handle_entropy(cleaned)
        root_node = EntityNode(
            entity_type=EntityType.PERSON if is_person else EntityType.USERNAME,
            value=cleaned,
            entropy_score=metrics.shannon_entropy,
            rarity_score=metrics.rarity_score,
            confidence=0.90,
        )

        nodes: list[EntityNode] = [root_node]
        edges: list[RelationshipEdge] = []
        evidence_items: list[EvidenceItem] = []
        errors: list[str] = []

        candidates = derive_handle_candidates(cleaned)
        if not candidates:
            return CollectorResult(
                collector_name=self.name,
                query=cleaned,
                nodes=nodes,
                edges=edges,
                evidence_items=evidence_items,
                errors=["No valid username candidates could be derived from query"],
            )

        semaphore = asyncio.Semaphore(self.config.max_concurrency)
        seen_profiles: set[tuple[str, str]] = set()

        async def _probe_platform(spec: PlatformSpec, candidate: str) -> None:
            if spec.regex_check:
                try:
                    if not re.search(spec.regex_check, candidate):
                        return
                except re.error:
                    return
            url = _format_handle_url(spec.api_url_template, candidate)
            req_headers = (
                {"Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"}
                if spec.response_kind == "text"
                else None
            )
            async with semaphore:
                try:
                    status, payload, ev_item, _, resp_headers = await self._fetch_with_custody_full(
                        url=url,
                        case_id=case_id,
                        ledger=active_ledger,
                        storage=storage,
                        headers=req_headers,
                        notes=f"Username probe on {spec.platform} for '{candidate}'",
                    )
                except Exception as exc:
                    errors.append(f"{spec.platform}: {type(exc).__name__}: {exc}")
                    return

                if status != spec.expected_status or ev_item is None:
                    return

                parsed = self._parse_platform_payload(
                    spec,
                    candidate,
                    payload,
                    headers=resp_headers,
                )
                if parsed is None:
                    return

                dedupe_key = (spec.platform.strip().lower(), str(parsed["username"]).strip().lower())
                if dedupe_key in seen_profiles:
                    return
                seen_profiles.add(dedupe_key)

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
                    confidence=0.88 if not is_person else 0.78,
                    attributes=profile_attrs,
                    evidence_ids=[ev_item.evidence_id],
                )
                nodes.append(profile_node)
                edges.append(
                    RelationshipEdge(
                        source_node_id=root_node.node_id,
                        target_node_id=profile_node.node_id,
                        relation_type=RelationType.HAS_PROFILE,
                        weight=0.90 if not is_person else 0.80,
                        confidence=0.88 if not is_person else 0.78,
                        rationale=f"Active {spec.platform} profile discovered for '{candidate}'",
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

        use_fast_subset = len(self.platforms) > len(_FAST_EXTENDED_VARIANT_PLATFORMS)
        tasks = []
        for idx, candidate in enumerate(candidates):
            for spec in self.platforms:
                if idx >= 3 and use_fast_subset and spec.platform not in _FAST_EXTENDED_VARIANT_PLATFORMS:
                    continue
                tasks.append(_probe_platform(spec, candidate))

        await asyncio.gather(*tasks)

        return CollectorResult(
            collector_name=self.name,
            query=cleaned,
            nodes=nodes,
            edges=edges,
            evidence_items=evidence_items,
            errors=errors,
        )
