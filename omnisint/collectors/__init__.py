"""Pluggable passive OSINT collectors and registry."""

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
from omnisint.collectors.search_dork_collector import (
    SearchDorkCollector,
    generate_dork_queries,
)
from omnisint.collectors.threat_intel import ThreatIntelCollector
from omnisint.collectors.username_collector import (
    DEFAULT_PLATFORM_SPECS,
    PlatformSpec,
    UsernameCollector,
    load_whatsmyname_specs,
)
from omnisint.config import OmniSINTSettings


def create_default_registry(
    config: CollectorConfig | None = None,
    settings: OmniSINTSettings | None = None,
    http_transport: HttpGetTransportCallable | None = None,
) -> CollectorRegistry:
    """Create a CollectorRegistry pre-populated with all OmniSINT passive collectors."""
    registry = CollectorRegistry()
    registry.register(UsernameCollector(config=config, settings=settings, http_transport=http_transport))
    registry.register(GitHubCollector(config=config, settings=settings, http_transport=http_transport))
    registry.register(DomainCTCollector(config=config, settings=settings, http_transport=http_transport))
    registry.register(ThreatIntelCollector(config=config, settings=settings, http_transport=http_transport))
    registry.register(SearchDorkCollector(config=config, settings=settings, http_transport=http_transport))
    return registry


__all__ = [
    "BaseCollector",
    "CollectorConfig",
    "CollectorRegistry",
    "DEFAULT_PLATFORM_SPECS",
    "DomainCTCollector",
    "GitHubCollector",
    "HttpGetTransportCallable",
    "HttpResponseData",
    "PlatformSpec",
    "SearchDorkCollector",
    "ThreatIntelCollector",
    "UsernameCollector",
    "create_default_registry",
    "generate_dork_queries",
    "load_whatsmyname_specs",
    "redact_sensitive_url",
]
