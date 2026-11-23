"""Pluggable passive OSINT collectors and registry."""

from typing import Sequence

from omnisint.collectors.base import (
    BaseCollector,
    CollectorConfig,
    CollectorRegistry,
    HttpGetTransportCallable,
    HttpResponseData,
    redact_sensitive_url,
)
from omnisint.collectors.domain_ct_collector import DomainCTCollector
from omnisint.collectors.github_collector import GitHubCollector
from omnisint.collectors.scrapling_collector import (
    ExtractedProfileMetadata,
    ScrapedPageData,
    ScraplingCollector,
    detect_access_gate,
    parse_public_profile_html,
)
from omnisint.collectors.search_dork_collector import (
    SearchDorkCollector,
    classify_social_profile_url,
    generate_dork_queries,
    parse_search_engine_html,
)
from omnisint.collectors.threat_intel import ThreatIntelCollector
from omnisint.collectors.username_collector import (
    DEFAULT_PLATFORM_SPECS,
    NAME_SHORT_FORMS,
    PlatformSpec,
    UsernameCollector,
    derive_handle_candidates,
    derive_search_name_variants,
    is_human_name_query,
    load_sherlock_specs,
    load_whatsmyname_specs,
    split_concatenated_name_tokens,
)
from omnisint.config import OmniSINTSettings


def create_default_registry(
    config: CollectorConfig | None = None,
    settings: OmniSINTSettings | None = None,
    http_transport: HttpGetTransportCallable | None = None,
    include_scrapling: bool = False,
    scrapling_dynamic: bool = False,
    username_platforms: Sequence[PlatformSpec] | None = None,
) -> CollectorRegistry:
    """Create a CollectorRegistry pre-populated with all OmniSINT passive collectors."""
    registry = CollectorRegistry()
    registry.register(
        UsernameCollector(
            platforms=username_platforms,
            config=config,
            settings=settings,
            http_transport=http_transport,
        )
    )
    registry.register(GitHubCollector(config=config, settings=settings, http_transport=http_transport))
    registry.register(DomainCTCollector(config=config, settings=settings, http_transport=http_transport))
    registry.register(ThreatIntelCollector(config=config, settings=settings, http_transport=http_transport))
    registry.register(SearchDorkCollector(config=config, settings=settings, http_transport=http_transport))
    if include_scrapling:
        registry.register(
            ScraplingCollector(
                use_dynamic_browser=scrapling_dynamic,
                config=config,
                settings=settings,
                http_transport=http_transport,
            )
        )
    return registry


__all__ = [
    "BaseCollector",
    "CollectorConfig",
    "CollectorRegistry",
    "DEFAULT_PLATFORM_SPECS",
    "DomainCTCollector",
    "ExtractedProfileMetadata",
    "GitHubCollector",
    "HttpGetTransportCallable",
    "HttpResponseData",
    "NAME_SHORT_FORMS",
    "PlatformSpec",
    "ScrapedPageData",
    "ScraplingCollector",
    "SearchDorkCollector",
    "ThreatIntelCollector",
    "UsernameCollector",
    "classify_social_profile_url",
    "create_default_registry",
    "derive_handle_candidates",
    "derive_search_name_variants",
    "detect_access_gate",
    "generate_dork_queries",
    "is_human_name_query",
    "load_sherlock_specs",
    "load_whatsmyname_specs",
    "parse_public_profile_html",
    "parse_search_engine_html",
    "redact_sensitive_url",
    "split_concatenated_name_tokens",
]
