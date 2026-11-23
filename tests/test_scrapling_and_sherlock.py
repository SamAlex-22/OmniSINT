"""Offline deterministic tests for Sherlock data.json support and ScraplingCollector."""

from __future__ import annotations

import ast
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from omnisint.api.routes.cases import OmniSINTAPIService
from omnisint.cli.main import run_cli
from omnisint.collectors import (
    DEFAULT_PLATFORM_SPECS,
    CollectorConfig,
    HttpResponseData,
    ScrapedPageData,
    ScraplingCollector,
    SearchDorkCollector,
    UsernameCollector,
    classify_social_profile_url,
    create_default_registry,
    derive_handle_candidates,
    detect_access_gate,
    load_sherlock_specs,
    parse_public_profile_html,
    parse_search_engine_html,
)
from omnisint.core.custody import CustodyLedger
from omnisint.core.models import EntityType, RelationType
from omnisint.core.orchestrator import infer_entity_type
from omnisint.core.storage import CaseStorage


SAMPLE_INSTAGRAM_PUBLIC_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Alex K (@alex_sec) • Instagram photos and videos</title>
  <meta property="og:title" content="Alex K (@alex_sec) • Instagram photos and videos" />
  <meta property="og:description" content="1,234 Followers, 567 Following, 89 Posts - Threat hunter @OmniSINT_Lab #OSINT #DFIR contact: alex.sec@proton.me" />
  <meta property="og:image" content="https://cdn.example.net/avatars/alex_sec.jpg" />
  <meta property="og:site_name" content="Instagram" />
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "ProfilePage",
    "mainEntity": {
      "@type": "Person",
      "name": "Alex K",
      "alternateName": "@alex_sec",
      "description": "Threat hunter @OmniSINT_Lab #OSINT #DFIR contact: alex.sec@proton.me",
      "image": "https://cdn.example.net/avatars/alex_sec.jpg",
      "email": "mailto:alex.sec@proton.me",
      "sameAs": [
        "https://alexsec.io",
        "https://github.com/alex_sec"
      ],
      "address": {
        "@type": "PostalAddress",
        "addressLocality": "Bengaluru",
        "addressCountry": "India"
      }
    }
  }
  </script>
</head>
<body>
  <a href="https://alexsec.io">Website</a>
  <a href="https://mastodon.social/@alex_sec">Mastodon</a>
  <a href="https://www.instagram.com/accounts/login/">Login Noise</a>
  <a href="https://twitter.com/intent/tweet?text=hi">Share Noise</a>
</body>
</html>
"""


class TestScraplingAndSherlock(unittest.IsolatedAsyncioTestCase):
    """Deterministic offline tests covering Sherlock data.json parsing and Scrapling integration."""

    def test_load_sherlock_specs_handles_schema_and_all_error_types(self) -> None:
        sherlock_data: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.schema.json",
            "CodeHost": {
                "url": "https://codehost.example/{}",
                "urlProbe": "https://api.codehost.example/u/{}",
                "errorType": "status_code",
                "regexCheck": "^[A-Za-z0-9_]{3,20}$",
            },
            "SoftForum": {
                "url": "https://forum.example/u/{}",
                "errorType": "message",
                "errorMsg": ["No such user", "Account suspended"],
            },
            "RedirectSocial": {
                "url": "https://redsocial.example/{}",
                "errorType": "response_url",
                "errorUrl": "https://redsocial.example/",
            },
            "BrokenNoPlaceholder": {
                "url": "https://broken.example/static",
                "errorType": "status_code",
            },
        }

        specs_from_dict = load_sherlock_specs(sherlock_data)
        self.assertEqual(len(specs_from_dict), 3)
        self.assertEqual([s.platform for s in specs_from_dict], ["CodeHost", "SoftForum", "RedirectSocial"])

        ch = specs_from_dict[0]
        self.assertEqual(ch.api_url_template, "https://api.codehost.example/u/{handle}")
        self.assertEqual(ch.profile_url_template, "https://codehost.example/{handle}")
        self.assertEqual(ch.error_type, "status_code")
        self.assertEqual(ch.regex_check, "^[A-Za-z0-9_]{3,20}$")

        sf = specs_from_dict[1]
        self.assertEqual(sf.error_type, "message")
        self.assertEqual(sf.missing_string, "No such user")
        self.assertEqual(sf.missing_strings, ["No such user", "Account suspended"])

        rs = specs_from_dict[2]
        self.assertEqual(rs.error_type, "response_url")
        self.assertEqual(rs.error_url, "https://redsocial.example/")

        # Verify file path loading and max_sites truncation
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = Path(tmpdir) / "data.json"
            json_path.write_text(json.dumps(sherlock_data), encoding="utf-8")
            limited = load_sherlock_specs(json_path, max_sites=2)
            self.assertEqual(len(limited), 2)
            self.assertEqual(load_sherlock_specs(json_path, max_sites=0), [])

    async def test_username_collector_executes_sherlock_specs_accurately(self) -> None:
        requested_urls: list[str] = []
        specs = load_sherlock_specs(
            {
                "RegexStrict": {
                    "url": "https://strict.example/{}",
                    "errorType": "status_code",
                    "regexCheck": "^only_letters$",
                },
                "PublicBlog": {
                    "url": "https://blog.example/@{}",
                    "errorType": "status_code",
                },
                "MessageCheck": {
                    "url": "https://msg.example/{}",
                    "errorType": "message",
                    "errorMsg": ["Profile missing", "User deleted"],
                },
                "RedirectHomeCheck": {
                    "url": "https://pins.example/{}",
                    "errorType": "response_url",
                    "errorUrl": "https://pins.example/",
                },
                "RedirectCanonCheck": {
                    "url": "https://canon.example/{}",
                    "errorType": "response_url",
                    "errorUrl": "https://canon.example/404",
                },
            }
        )

        async def _mock_get(
            url: str,
            headers: dict[str, str] | None,
            params: dict[str, Any] | None,
            timeout: float,
        ) -> HttpResponseData:
            requested_urls.append(url)
            if "blog.example/@alex_sec" in url:
                return HttpResponseData(
                    status_code=200,
                    body=(
                        '<html><head><title>Alex Blog</title>'
                        '<meta property="og:description" content="Hardware & OSINT notes" />'
                        '<meta property="og:image" content="" /></head></html>'
                    ),
                )
            if "msg.example/alex_sec" in url:
                return HttpResponseData(status_code=200, body="<html>Notice: User deleted by owner</html>")
            if "pins.example/alex_sec" in url:
                # Redirect target is root home page => user NOT found
                return HttpResponseData(
                    status_code=200,
                    body="<html>Home</html>",
                    headers={"x-final-url": "https://pins.example/"},
                )
            if "canon.example/alex_sec" in url:
                # Real profile URL => user EXISTS (canonical does not match /404)
                return HttpResponseData(
                    status_code=200,
                    body='<html><head><link rel="canonical" href="https://canon.example/alex_sec" /></head></html>',
                    headers={"x-final-url": "https://canon.example/alex_sec"},
                )
            return HttpResponseData(status_code=404, body="Not Found")

        ledger = CustodyLedger(case_id="case-sherlock-01")
        collector = UsernameCollector(
            platforms=specs,
            config=CollectorConfig(rate_limit_per_second=100.0),
            http_transport=_mock_get,
            fetch_avatars=False,
        )
        result = await collector.collect("alex_sec", case_id="case-sherlock-01", ledger=ledger)

        # RegexStrict should not even issue a request for "alex_sec"
        self.assertFalse(any("strict.example" in u for u in requested_urls))

        profiles = [n for n in result.nodes if n.entity_type == EntityType.SOCIAL_PROFILE]
        found_platforms = {p.platform for p in profiles}
        self.assertEqual(found_platforms, {"PublicBlog", "RedirectCanonCheck"})

        blog_node = next(p for p in profiles if p.platform == "PublicBlog")
        self.assertEqual(blog_node.attributes["display_name"], "Alex Blog")
        self.assertEqual(blog_node.attributes["bio"], "Hardware & OSINT notes")
        self.assertTrue(ledger.verify_chain()[0])

    def test_parse_public_profile_html_extracts_rich_social_metadata(self) -> None:
        meta = parse_public_profile_html(
            SAMPLE_INSTAGRAM_PUBLIC_HTML,
            url="https://www.instagram.com/alex_sec/",
            use_scrapling_selector=False,
        )
        self.assertEqual(meta.platform, "Instagram")
        self.assertEqual(meta.display_name, "Alex K")
        self.assertEqual(meta.follower_count, 1234)
        self.assertEqual(meta.following_count, 567)
        self.assertEqual(meta.post_count, 89)
        self.assertIn("@OmniSINT_Lab", meta.mentions)
        self.assertIn("@alex_sec", meta.mentions)
        self.assertIn("#OSINT", meta.hashtags)
        self.assertIn("#DFIR", meta.hashtags)
        self.assertEqual(meta.emails, ["alex.sec@proton.me"])
        self.assertEqual(meta.locations, ["Bengaluru, India"])
        self.assertIn("https://alexsec.io", meta.external_links)
        self.assertIn("https://github.com/alex_sec", meta.external_links)
        self.assertIn("https://mastodon.social/@alex_sec", meta.external_links)
        self.assertFalse(any("accounts/login" in u for u in meta.external_links))
        self.assertFalse(any("intent/tweet" in u for u in meta.external_links))
        self.assertEqual(meta.json_ld_types, ["ProfilePage", "Person"])

        # Compact "K" multiplier parsing check
        compact_html = '<meta property="og:description" content="12.5K Followers, 2M Following, 14 Posts" />'
        compact_meta = parse_public_profile_html(compact_html, url="https://instagram.com/big_acct/")
        self.assertEqual(compact_meta.follower_count, 12500)
        self.assertEqual(compact_meta.following_count, 2000000)
        self.assertEqual(compact_meta.post_count, 14)

    def test_detect_access_gate_and_verify_no_stealth_bypass_code(self) -> None:
        self.assertEqual(detect_access_gate(429, "Too Many Requests"), "http_429_rate_limited")
        self.assertEqual(detect_access_gate(401, "Unauthorized"), "http_401_unauthorized")
        self.assertEqual(detect_access_gate(403, "Forbidden"), "http_403_forbidden")
        self.assertEqual(
            detect_access_gate(200, "<html>Login</html>", "https://www.instagram.com/accounts/login/?next=/a/"),
            "login_wall",
        )
        self.assertEqual(
            detect_access_gate(200, '<div class="cf-turnstile">Verify you are human</div>', "https://example.com"),
            "captcha_or_antibot_gate",
        )
        self.assertEqual(
            detect_access_gate(200, '<div class="g-recaptcha"></div>', "https://example.com"),
            "captcha_or_antibot_gate",
        )
        self.assertIsNone(detect_access_gate(200, SAMPLE_INSTAGRAM_PUBLIC_HTML, "https://www.instagram.com/alex_sec/"))

        # Enforce AGENTS.md compliance: StealthyFetcher / solve_cloudflare must never exist in AST or module symbols
        collector_path = Path("/Users/alex/OmniSINT/omnisint/collectors/scrapling_collector.py")
        tree = ast.parse(collector_path.read_text(encoding="utf-8"))
        referenced_symbols: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                referenced_symbols.add(node.id)
            elif isinstance(node, ast.Attribute):
                referenced_symbols.add(node.attr)
            elif isinstance(node, ast.alias):
                referenced_symbols.add(node.name.split(".")[-1])
        self.assertNotIn("StealthyFetcher", referenced_symbols)
        self.assertNotIn("solve_cloudflare", referenced_symbols)

    async def test_scrapling_collector_url_and_gated_handling(self) -> None:
        avatar_bytes = b"SCRAPLING_AVATAR_BYTES_" * 16

        async def _mock_page_fetcher(url: str, use_dynamic: bool) -> ScrapedPageData:
            if "instagram.com/alex_sec" in url:
                return ScrapedPageData(
                    url=url,
                    final_url="https://www.instagram.com/alex_sec/",
                    status_code=200,
                    html=SAMPLE_INSTAGRAM_PUBLIC_HTML,
                    fetcher_used="scrapling_dynamic" if use_dynamic else "scrapling_fetcher",
                )
            if "blocked.example" in url:
                return ScrapedPageData(
                    url=url,
                    final_url=url,
                    status_code=403,
                    html="<html>Access denied - Attention Required! | Cloudflare</html>",
                    fetcher_used="scrapling_fetcher",
                )
            return ScrapedPageData(
                url=url,
                final_url="https://example.org/research",
                status_code=200,
                html="<html><head><title>OSINT Lab Notes</title></head><body><a href='https://partner.org'>Partner</a></body></html>",
                fetcher_used="scrapling_fetcher",
            )

        async def _mock_avatar_http(
            url: str,
            headers: dict[str, str] | None,
            params: dict[str, Any] | None,
            timeout: float,
        ) -> HttpResponseData:
            return HttpResponseData(status_code=200, body={"bytes_hex": avatar_bytes.hex()})

        ledger = CustodyLedger(case_id="case-scrapling-url")
        collector = ScraplingCollector(
            use_dynamic_browser=True,
            page_fetcher=_mock_page_fetcher,
            http_transport=_mock_avatar_http,
            config=CollectorConfig(rate_limit_per_second=100.0),
        )
        res = await collector.collect("https://www.instagram.com/alex_sec/", case_id="case-scrapling-url", ledger=ledger)

        self.assertEqual(res.errors, [])
        self.assertEqual(len(res.evidence_items), 1)
        self.assertTrue(ledger.verify_chain()[0])

        profiles = [n for n in res.nodes if n.entity_type == EntityType.SOCIAL_PROFILE]
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0].platform, "Instagram")
        self.assertEqual(profiles[0].value, "alex_sec")
        self.assertEqual(profiles[0].attributes["fetcher_used"], "scrapling_dynamic")
        self.assertEqual(profiles[0].attributes["follower_count"], 1234)
        self.assertTrue(any(n.entity_type == EntityType.AVATAR_HASH for n in res.nodes))
        self.assertTrue(any(n.entity_type == EntityType.EMAIL and n.value == "alex.sec@proton.me" for n in res.nodes))
        self.assertTrue(any(n.entity_type == EntityType.LOCATION and n.value == "Bengaluru, India" for n in res.nodes))
        self.assertTrue(any(e.relation_type == RelationType.MENTIONED_AT for e in res.edges))

        # Generic URL emits EntityType.URL (not SOCIAL_PROFILE)
        generic_res = await collector.collect("https://example.org/research", case_id="case-generic")
        self.assertTrue(any(n.entity_type == EntityType.URL and n.value == "https://example.org/research" for n in generic_res.nodes))
        self.assertFalse(any(n.entity_type == EntityType.SOCIAL_PROFILE for n in generic_res.nodes))

        # Gated page halts cleanly with zero profile nodes
        blocked_res = await collector.collect("https://blocked.example/u/alex", case_id="case-blocked")
        self.assertEqual(len(blocked_res.evidence_items), 0)
        self.assertEqual(len(blocked_res.nodes), 0)
        self.assertEqual(len(blocked_res.errors), 1)
        self.assertIn("skipped without bypass", blocked_res.errors[0])

    async def test_scrapling_collector_username_mode_partial_success(self) -> None:
        async def _mock_fetcher(url: str, use_dynamic: bool) -> ScrapedPageData:
            if "instagram.com" in url:
                return ScrapedPageData(
                    url=url,
                    final_url="https://www.instagram.com/accounts/login/",
                    status_code=200,
                    html="<html>Log in to Instagram</html>",
                    fetcher_used="scrapling_fetcher",
                )
            if "github.com" in url:
                return ScrapedPageData(
                    url=url,
                    final_url=url,
                    status_code=200,
                    html='<html><head><meta property="og:title" content="alex_sec (Alex K)" /></head></html>',
                    fetcher_used="scrapling_fetcher",
                )
            return ScrapedPageData(url=url, final_url=url, status_code=404, html="", fetcher_used="scrapling_fetcher")

        collector = ScraplingCollector(
            page_fetcher=_mock_fetcher,
            fetch_avatars=False,
            config=CollectorConfig(rate_limit_per_second=100.0),
        )
        res = await collector.collect("@alex_sec", case_id="case-scrapling-user")

        self.assertEqual(len(res.errors), 1)
        self.assertIn("Instagram: access gated (login_wall)", res.errors[0])
        profiles = [n for n in res.nodes if n.entity_type == EntityType.SOCIAL_PROFILE]
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0].platform, "GitHub")
        self.assertTrue(any(e.relation_type == RelationType.HAS_PROFILE for e in res.edges))

    def test_registry_default_backward_compatibility_and_cli_help(self) -> None:
        self.assertEqual(len(create_default_registry().list_collectors()), 5)
        self.assertEqual(len(create_default_registry(include_scrapling=True).list_collectors()), 6)

        code_scan, out_scan = run_cli(["scan", "--help"])
        self.assertEqual(code_scan, 0)
        self.assertIn("--sherlock-file", out_scan)
        self.assertIn("--wmn-file", out_scan)
        self.assertIn("--scrapling", out_scan)
        self.assertIn("--dynamic", out_scan)

        code_scrape, out_scrape = run_cli(["scrape", "--help"])
        self.assertEqual(code_scrape, 0)
        self.assertIn("--dynamic", out_scrape)
        self.assertIn("--db", out_scrape)
        self.assertIn("--title", out_scrape)

    def test_classify_social_profile_url_and_search_engine_html_parser(self) -> None:
        self.assertEqual(
            classify_social_profile_url("https://www.linkedin.com/in/sam-alex-22/"),
            ("LinkedIn", "sam-alex-22"),
        )
        self.assertEqual(
            classify_social_profile_url("https://www.instagram.com/samalex/"),
            ("Instagram", "samalex"),
        )
        self.assertEqual(
            classify_social_profile_url("https://x.com/samalex_sec"),
            ("Twitter", "samalex_sec"),
        )
        self.assertEqual(
            classify_social_profile_url("https://github.com/SamAlex-22"),
            ("GitHub", "SamAlex-22"),
        )
        self.assertEqual(
            classify_social_profile_url("https://medium.com/@samalex"),
            ("Medium", "samalex"),
        )
        self.assertEqual(
            classify_social_profile_url("https://www.youtube.com/@samalex"),
            ("YouTube", "samalex"),
        )
        # Non-profile & gist URLs must not be misclassified
        self.assertIsNone(classify_social_profile_url("https://www.linkedin.com/company/acme/"))
        self.assertIsNone(classify_social_profile_url("https://www.instagram.com/accounts/login/"))
        self.assertIsNone(classify_social_profile_url("https://www.youtube.com/watch?v=12345"))
        self.assertIsNone(classify_social_profile_url("https://gist.github.com/krypton_sec/12345"))

        ddg_and_yahoo_html = """
        <html><body>
          <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.linkedin.com%2Fin%2Fsam-alex%2F&amp;rut=1">Sam Alex | LinkedIn</a>
          <a href="https://r.search.yahoo.com/_ylt=A0/RV=2/RU=https%3a%2f%2finstagram.com%2fsamalex%2f/RK=2/RS=1">Sam Alex (@samalex)</a>
          <a href="https://html.duckduckgo.com/html/?q=internal">Internal DDG Nav</a>
          <a href="https://medium.com/@samalex">Sam Alex - Medium</a>
        </body></html>
        """
        hits = parse_search_engine_html(ddg_and_yahoo_html)
        urls = [h["url"] for h in hits]
        self.assertEqual(
            urls,
            [
                "https://www.linkedin.com/in/sam-alex/",
                "https://instagram.com/samalex/",
                "https://medium.com/@samalex",
            ],
        )

    async def test_search_dork_collector_real_name_github_and_ddg_without_api_keys(self) -> None:
        async def _mock_web(
            url: str,
            headers: dict[str, str] | None,
            params: dict[str, Any] | None,
            timeout: float,
        ) -> HttpResponseData:
            if "api.github.com/search/users" in url:
                return HttpResponseData(
                    status_code=200,
                    body={
                        "total_count": 1,
                        "items": [
                            {
                                "login": "SamAlex-22",
                                "html_url": "https://github.com/SamAlex-22",
                                "avatar_url": "https://avatars.githubusercontent.com/u/1?v=4",
                                "score": 1.0,
                            }
                        ],
                    },
                )
            if "html.duckduckgo.com/html/" in url:
                return HttpResponseData(
                    status_code=200,
                    body=(
                        '<a class="result__a" href="//duckduckgo.com/l/?uddg='
                        'https%3A%2F%2Fwww.linkedin.com%2Fin%2Fsam-alex-sec%2F&amp;rut=a">'
                        "Sam Alex - Cybersecurity | LinkedIn</a>"
                    ),
                )
            return HttpResponseData(status_code=404, body="")

        ledger = CustodyLedger(case_id="case-name-01")
        collector = SearchDorkCollector(
            config=CollectorConfig(rate_limit_per_second=100.0),
            http_transport=_mock_web,
        )
        res = await collector.collect("Sam Alex", case_id="case-name-01", ledger=ledger)

        self.assertEqual(res.errors, [])
        self.assertTrue(ledger.verify_chain()[0])

        profiles = {(n.platform, n.value) for n in res.nodes if n.entity_type == EntityType.SOCIAL_PROFILE}
        self.assertIn(("GitHub", "SamAlex-22"), profiles)
        self.assertIn(("LinkedIn", "sam-alex-sec"), profiles)
        usernames = {n.value for n in res.nodes if n.entity_type == EntityType.USERNAME}
        self.assertIn("SamAlex-22", usernames)
        self.assertTrue(any(e.relation_type == RelationType.HAS_PROFILE for e in res.edges))
        self.assertTrue(any(e.relation_type == RelationType.HAS_HANDLE for e in res.edges))

    def test_handle_candidates_person_type_and_api_default_scrapling(self) -> None:
        self.assertEqual(
            derive_handle_candidates("Sam Alex"),
            ["samalex", "sam_alex", "sam-alex"],
        )
        self.assertEqual(derive_handle_candidates("@SamAlex-22"), ["SamAlex-22"])
        self.assertEqual(infer_entity_type("Sam Alex"), EntityType.PERSON)
        self.assertGreaterEqual(len(DEFAULT_PLATFORM_SPECS), 20)
        for spec in DEFAULT_PLATFORM_SPECS:
            if spec.response_kind == "text":
                self.assertTrue(spec.existence_string, f"{spec.platform} text spec must guard existence_string")

        service = OmniSINTAPIService(storage=CaseStorage(":memory:"))
        self.assertIsNotNone(service.orchestrator.registry.get("scrapling_collector"))


if __name__ == "__main__":
    unittest.main()
