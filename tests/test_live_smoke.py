"""Opt-in live-network smoke tests (skipped offline unless OMNISINT_LIVE_TESTS=1)."""

from __future__ import annotations

import os
import unittest

from omnisint.collectors import DomainCTCollector, GitHubCollector
from omnisint.core.models import EntityType


@unittest.skipUnless(
    os.getenv("OMNISINT_LIVE_TESTS") == "1",
    "Set OMNISINT_LIVE_TESTS=1 to execute live-internet collector smoke tests.",
)
class TestLiveCollectorSmoke(unittest.IsolatedAsyncioTestCase):
    """Real-network sanity checks against public GitHub and Google DoH APIs."""

    async def test_live_github_and_doh_smoke(self) -> None:
        gh = GitHubCollector()
        gh_res = await gh.collect("torvalds", case_id="live-smoke-gh")
        self.assertTrue(any(n.entity_type == EntityType.SOCIAL_PROFILE for n in gh_res.nodes))
        self.assertGreaterEqual(len(gh_res.evidence_items), 1)

        dom = DomainCTCollector()
        dom_res = await dom.collect("example.com", case_id="live-smoke-dom")
        self.assertTrue(any(n.entity_type == EntityType.IP_ADDRESS for n in dom_res.nodes))


if __name__ == "__main__":
    unittest.main()
