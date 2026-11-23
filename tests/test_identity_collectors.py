"""Unit tests for Task 6: Pluggable Collector Framework, UsernameCollector & GitHubCollector."""

from __future__ import annotations

import unittest
from typing import Any

from omnisint.collectors import (
    CollectorConfig,
    CollectorRegistry,
    GitHubCollector,
    HttpResponseData,
    UsernameCollector,
    load_whatsmyname_specs,
    redact_sensitive_url,
)
from omnisint.core.custody import CustodyLedger
from omnisint.core.models import Case, EntityType, RelationType
from omnisint.core.storage import CaseStorage


class TestIdentityCollectors(unittest.IsolatedAsyncioTestCase):
    """Offline deterministic tests for BaseCollector, CollectorRegistry, UsernameCollector, and GitHubCollector."""

    async def test_collector_registry_and_ttl_cache_deduplication(self) -> None:
        call_count = 0

        async def _mock_get(
            url: str,
            headers: dict[str, str] | None,
            params: dict[str, Any] | None,
            timeout: float,
        ) -> HttpResponseData:
            nonlocal call_count
            call_count += 1
            if "api.github.com/users/krypton_sec_x7" == url.removeprefix("https://"):
                return HttpResponseData(
                    status_code=200,
                    body={
                        "login": "krypton_sec_x7",
                        "name": "Alex K.",
                        "bio": "Threat Hunter",
                        "location": "Bengaluru, India",
                        "avatar_hash": "8f3c3c1e1e0f0f00",
                    },
                )
            return HttpResponseData(status_code=404, body={"message": "Not Found"})

        async with CaseStorage(":memory:") as storage:
            case = await storage.create_case(
                title="Collector Cache Test",
                target_query="krypton_sec_x7",
            )
            cfg = CollectorConfig(rate_limit_per_second=100.0, use_cache=True, cache_ttl_seconds=3600)
            u_collector = UsernameCollector(config=cfg, http_transport=_mock_get)

            registry = CollectorRegistry()
            registry.register(u_collector)
            self.assertEqual(registry.get("username_collector"), u_collector)
            self.assertEqual(registry.get_for_entity_type(EntityType.USERNAME), [u_collector])

            # First collect hits transport once per platform
            res1 = await u_collector.collect("krypton_sec_x7", case.case_id, storage=storage)
            first_calls = call_count
            self.assertGreater(first_calls, 0)
            self.assertTrue(any(n.entity_type == EntityType.SOCIAL_PROFILE for n in res1.nodes))
            self.assertTrue(any(n.entity_type == EntityType.AVATAR_HASH for n in res1.nodes))

            # Second collect hits TTL cache for GitHub 200 response
            res2 = await u_collector.collect("krypton_sec_x7", case.case_id, storage=storage)
            self.assertEqual(len(res2.evidence_items), 1)
            self.assertLess(call_count - first_calls, first_calls)

    async def test_username_collector_extracts_profiles_and_avatar_dhash(self) -> None:
        avatar_bytes = b"OMNISINT_TEST_AVATAR_BYTES_" * 16

        async def _mock_get(
            url: str,
            headers: dict[str, str] | None,
            params: dict[str, Any] | None,
            timeout: float,
        ) -> HttpResponseData:
            if "api.github.com/users/x7_krypton_99" in url:
                return HttpResponseData(
                    status_code=200,
                    body={
                        "login": "x7_krypton_99",
                        "name": "Alex K",
                        "location": "Bengaluru, India",
                        "avatar_bytes_hex": avatar_bytes.hex(),
                        "created_at": "2024-01-10T09:00:00Z",
                    },
                )
            if "reddit.com/user/x7_krypton_99/about.json" in url:
                return HttpResponseData(
                    status_code=200,
                    body={
                        "data": {
                            "name": "x7_krypton_99",
                            "subreddit": {"title": "Krypton", "public_description": "OSINT & DFIR"},
                            "avatar_hash": "8f3c3c1e1e0f0f00",
                            "timestamps": ["2026-05-04T14:15:00+05:30"],
                        }
                    },
                )
            if "keybase.io" in url:
                return HttpResponseData(
                    status_code=200,
                    body={
                        "status": {"code": 0},
                        "them": [
                            {
                                "basics": {"username": "x7_krypton_99"},
                                "profile": {"full_name": "Alex K", "bio": "Sec"},
                            }
                        ],
                    },
                )
            return HttpResponseData(status_code=404, body={"error": "not found"})

        ledger = CustodyLedger(case_id="case-u-01")
        collector = UsernameCollector(
            config=CollectorConfig(rate_limit_per_second=100.0),
            http_transport=_mock_get,
        )
        result = await collector.collect("x7_krypton_99", case_id="case-u-01", ledger=ledger)

        self.assertEqual(result.errors, [])
        profiles = [n for n in result.nodes if n.entity_type == EntityType.SOCIAL_PROFILE]
        avatars = [n for n in result.nodes if n.entity_type == EntityType.AVATAR_HASH]
        self.assertEqual({p.platform for p in profiles}, {"GitHub", "Reddit", "Keybase"})
        self.assertEqual(len(avatars), 2)
        self.assertEqual(len(result.evidence_items), 3)
        self.assertTrue(ledger.verify_chain()[0])

    async def test_github_collector_extracts_commit_emails_repos_and_ssh_gpg_keys(self) -> None:
        async def _mock_gh(
            url: str,
            headers: dict[str, str] | None,
            params: dict[str, Any] | None,
            timeout: float,
        ) -> HttpResponseData:
            if url == "https://api.github.com/users/krypton_sec":
                return HttpResponseData(
                    status_code=200,
                    body={
                        "login": "krypton_sec",
                        "name": "Alex K.",
                        "company": "@OmniSINT-Lab",
                        "blog": "https://alexsec.io",
                        "location": "Bengaluru, India",
                        "created_at": "2023-03-01T10:00:00Z",
                    },
                )
            if url == "https://api.github.com/users/krypton_sec/repos":
                return HttpResponseData(
                    status_code=200,
                    body=[
                        {
                            "full_name": "krypton_sec/omnisint",
                            "language": "Python",
                            "stargazers_count": 120,
                            "fork": False,
                        }
                    ],
                )
            if url == "https://api.github.com/users/krypton_sec/events/public":
                return HttpResponseData(
                    status_code=200,
                    body=[
                        {
                            "type": "PushEvent",
                            "created_at": "2026-05-05T15:30:00+05:30",
                            "repo": {"name": "krypton_sec/omnisint"},
                            "payload": {
                                "commits": [
                                    {
                                        "timestamp": "2026-05-05T15:28:00+05:30",
                                        "author": {
                                            "name": "Alex",
                                            "email": "krypton@alexsec.io",
                                        },
                                    }
                                ]
                            },
                        }
                    ],
                )
            if url == "https://github.com/krypton_sec.keys":
                return HttpResponseData(
                    status_code=200,
                    body="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyMaterialForUnitTests\n",
                )
            if url == "https://api.github.com/users/krypton_sec/gpg_keys":
                return HttpResponseData(
                    status_code=200,
                    body=[
                        {
                            "key_id": "99AABBCC11223344",
                            "primary_key_id": "99AABBCC11223344",
                            "emails": [{"email": "krypton@proton.me", "verified": True}],
                        }
                    ],
                )
            return HttpResponseData(status_code=404, body={})

        ledger = CustodyLedger(case_id="case-gh-01")
        gh_collector = GitHubCollector(
            config=CollectorConfig(rate_limit_per_second=100.0),
            http_transport=_mock_gh,
        )
        result = await gh_collector.collect("krypton_sec", case_id="case-gh-01", ledger=ledger)

        self.assertEqual(result.errors, [])
        types_present = {n.entity_type for n in result.nodes}
        self.assertEqual(
            types_present,
            {
                EntityType.SOCIAL_PROFILE,
                EntityType.EMAIL,
                EntityType.ORGANIZATION,
                EntityType.DOMAIN,
                EntityType.REPOSITORY,
                EntityType.SSH_KEY,
                EntityType.PGP_KEY,
            },
        )
        emails = {n.value for n in result.nodes if n.entity_type == EntityType.EMAIL}
        self.assertEqual(emails, {"krypton@alexsec.io", "krypton@proton.me"})
        rel_types = {e.relation_type for e in result.edges}
        self.assertIn(RelationType.OWNS_REPO, rel_types)
        self.assertIn(RelationType.USES_KEY, rel_types)
        self.assertIn(RelationType.HAS_EMAIL, rel_types)
        self.assertIn(RelationType.OWNS_DOMAIN, rel_types)
        self.assertEqual(len(result.evidence_items), 5)
        self.assertTrue(ledger.verify_chain()[0])

    async def test_whatsmyname_loader_avatar_url_fetch_and_url_secret_redaction(self) -> None:
        # 1. Sensitive query parameter redaction
        raw_url = "https://www.googleapis.com/customsearch/v1?key=SECRET123&cx=mycx&q=test"
        redacted = redact_sensitive_url(raw_url)
        self.assertNotIn("SECRET123", redacted)
        self.assertIn("key=REDACTED", redacted)
        self.assertIn("cx=mycx", redacted)

        # 2. WhatsMyName JSON site loader + avatar_url download dHash computation
        wmn_payload = {
            "sites": [
                {
                    "name": "ExampleForum",
                    "uri_check": "https://exampleforum.test/u/{account}",
                    "uri_pretty": "https://exampleforum.test/@{account}",
                    "e_code": 200,
                    "e_string": "User Profile Found",
                    "m_string": "No such user",
                    "cat": "tech",
                }
            ]
        }
        wmn_specs = load_whatsmyname_specs(wmn_payload)
        self.assertEqual(len(wmn_specs), 1)

        avatar_raw = b"PNG_AVATAR_BYTES_SAMPLE_" * 12

        async def _mock_wmn_and_avatar(
            url: str,
            headers: dict[str, str] | None,
            params: dict[str, Any] | None,
            timeout: float,
        ) -> HttpResponseData:
            if "exampleforum.test/u/x7_krypton_99" in url:
                return HttpResponseData(status_code=200, body="<html>User Profile Found</html>")
            if "api.github.com/users/x7_krypton_99" in url:
                return HttpResponseData(
                    status_code=200,
                    body={
                        "login": "x7_krypton_99",
                        "avatar_url": "https://avatars.test/u/12345.png",
                    },
                )
            if url == "https://avatars.test/u/12345.png":
                return HttpResponseData(status_code=200, body={"bytes_hex": avatar_raw.hex()})
            return HttpResponseData(status_code=404, body="No such user")

        gh_only_plus_wmn = wmn_specs + [
            s for s in UsernameCollector().platforms if s.platform == "GitHub"
        ]
        collector = UsernameCollector(
            platforms=gh_only_plus_wmn,
            config=CollectorConfig(rate_limit_per_second=100.0),
            http_transport=_mock_wmn_and_avatar,
            fetch_avatars=True,
        )
        res = await collector.collect("x7_krypton_99", case_id="case-wmn-01")
        platforms = {n.platform for n in res.nodes if n.entity_type == EntityType.SOCIAL_PROFILE}
        self.assertEqual(platforms, {"ExampleForum", "GitHub"})
        avatars = [n for n in res.nodes if n.entity_type == EntityType.AVATAR_HASH]
        self.assertEqual(len(avatars), 1)
        self.assertEqual(len(avatars[0].value), 16)


if __name__ == "__main__":
    unittest.main()
