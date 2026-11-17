"""Passive GitHub profile, repository, commit author email, and SSH/PGP key collector."""

from __future__ import annotations

import urllib.parse
from typing import Any

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


class GitHubCollector(BaseCollector):
    """Collects GitHub profile metadata, repositories, commit emails/timestamps, and SSH/PGP keys."""

    name = "github_collector"
    description = "Extracts GitHub profile, repos, commit emails/timezones, and public SSH/GPG keys."
    supported_types = (EntityType.USERNAME, EntityType.SOCIAL_PROFILE)

    def __init__(
        self,
        config: CollectorConfig | None = None,
        settings: OmniSINTSettings | None = None,
        http_transport: HttpGetTransportCallable | None = None,
    ) -> None:
        super().__init__(config=config, settings=settings, http_transport=http_transport)

    def _github_headers(self) -> dict[str, str]:
        """Build GitHub REST API headers including optional personal access token."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.settings.github_token:
            headers["Authorization"] = f"Bearer {self.settings.github_token}"
        return headers

    @staticmethod
    def _extract_domain_from_url(raw_url: str) -> str | None:
        """Extract normalized hostname from a profile blog or homepage URL."""
        candidate = raw_url.strip()
        if not candidate:
            return None
        if "://" not in candidate:
            candidate = f"https://{candidate}"
        parsed = urllib.parse.urlparse(candidate)
        host = (parsed.netloc or "").split(":")[0].strip().lower()
        if host.startswith("www."):
            host = host[4:]
        if "." in host and not host.endswith("github.com") and not host.endswith("github.io"):
            return host
        return None

    async def collect(
        self,
        query: str,
        case_id: str,
        ledger: CustodyLedger | None = None,
        storage: CaseStorage | None = None,
    ) -> CollectorResult:
        """Collect public GitHub intelligence for username `query`."""
        username = query.strip().lstrip("@")
        if ":" in username and username.lower().startswith("github:"):
            username = username.split(":", 1)[1].strip()

        active_ledger = ledger if ledger is not None else CustodyLedger(case_id=case_id)
        if not username:
            return CollectorResult(
                collector_name=self.name,
                query=query,
                errors=["GitHub username query cannot be empty"],
            )

        headers = self._github_headers()
        nodes: list[EntityNode] = []
        edges: list[RelationshipEdge] = []
        evidence_items: list[EvidenceItem] = []
        errors: list[str] = []

        # 1. Fetch primary GitHub user profile
        profile_url = f"https://api.github.com/users/{username}"
        try:
            status, profile_payload, ev_profile, _ = await self.fetch_with_custody(
                url=profile_url,
                case_id=case_id,
                ledger=active_ledger,
                storage=storage,
                headers=headers,
                notes=f"GitHub profile metadata for '{username}'",
            )
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                query=username,
                errors=[f"GitHub profile fetch failed: {type(exc).__name__}: {exc}"],
            )

        if status != 200 or not isinstance(profile_payload, dict) or not profile_payload.get("login"):
            return CollectorResult(
                collector_name=self.name,
                query=username,
                errors=[f"GitHub user '{username}' not found (status={status})"],
            )

        assert ev_profile is not None
        evidence_items.append(ev_profile)
        login = str(profile_payload["login"])
        metrics = analyze_handle_entropy(login)

        timestamps: list[str] = []
        if profile_payload.get("created_at"):
            timestamps.append(str(profile_payload["created_at"]))

        profile_attrs: dict[str, Any] = {
            "url": profile_payload.get("html_url") or f"https://github.com/{login}",
            "display_name": profile_payload.get("name") or login,
            "bio": profile_payload.get("bio") or "",
            "public_repos": profile_payload.get("public_repos", 0),
            "followers": profile_payload.get("followers", 0),
            "timestamps": timestamps,
        }
        if profile_payload.get("location"):
            profile_attrs["location"] = str(profile_payload["location"])
        if profile_payload.get("avatar_url"):
            profile_attrs["avatar_url"] = str(profile_payload["avatar_url"])
        if profile_payload.get("avatar_hash"):
            profile_attrs["avatar_hash"] = str(profile_payload["avatar_hash"])

        profile_node = EntityNode(
            entity_type=EntityType.SOCIAL_PROFILE,
            value=login,
            platform="GitHub",
            entropy_score=metrics.shannon_entropy,
            rarity_score=metrics.rarity_score,
            confidence=0.95,
            attributes=profile_attrs,
            evidence_ids=[ev_profile.evidence_id],
        )
        nodes.append(profile_node)

        email_nodes_by_addr: dict[str, EntityNode] = {}

        def _add_email_node(raw_email: str, source_desc: str, ev_id: str, conf: float) -> None:
            addr = raw_email.strip().lower()
            if not addr or "@" not in addr:
                return
            is_noreply = addr.endswith("users.noreply.github.com")
            eff_conf = min(conf, 0.60) if is_noreply else conf
            if addr in email_nodes_by_addr:
                existing = email_nodes_by_addr[addr]
                if ev_id not in existing.evidence_ids:
                    existing.evidence_ids.append(ev_id)
                existing.confidence = max(existing.confidence, eff_conf)
                return

            em_metrics = analyze_handle_entropy(addr)
            em_node = EntityNode(
                entity_type=EntityType.EMAIL,
                value=addr,
                entropy_score=em_metrics.shannon_entropy,
                rarity_score=em_metrics.rarity_score,
                confidence=eff_conf,
                attributes={"source": source_desc, "is_noreply": is_noreply},
                evidence_ids=[ev_id],
            )
            email_nodes_by_addr[addr] = em_node
            nodes.append(em_node)
            edges.append(
                RelationshipEdge(
                    source_node_id=profile_node.node_id,
                    target_node_id=em_node.node_id,
                    relation_type=RelationType.HAS_EMAIL,
                    weight=eff_conf,
                    confidence=eff_conf,
                    rationale=f"Email '{addr}' extracted from {source_desc}",
                    evidence_ids=[ev_id],
                )
            )
            if not is_noreply and "email" not in profile_node.attributes:
                profile_node.attributes["email"] = addr

        if isinstance(profile_payload.get("email"), str) and profile_payload["email"].strip():
            _add_email_node(profile_payload["email"], "GitHub profile", ev_profile.evidence_id, 0.95)

        if isinstance(profile_payload.get("company"), str) and profile_payload["company"].strip():
            org_name = profile_payload["company"].strip().lstrip("@")
            org_node = EntityNode(
                entity_type=EntityType.ORGANIZATION,
                value=org_name,
                confidence=0.85,
                evidence_ids=[ev_profile.evidence_id],
            )
            nodes.append(org_node)
            edges.append(
                RelationshipEdge(
                    source_node_id=profile_node.node_id,
                    target_node_id=org_node.node_id,
                    relation_type=RelationType.MEMBER_OF,
                    weight=0.85,
                    confidence=0.85,
                    rationale=f"Company affiliation listed on GitHub profile '{login}'",
                    evidence_ids=[ev_profile.evidence_id],
                )
            )

        if isinstance(profile_payload.get("blog"), str) and profile_payload["blog"].strip():
            blog_domain = self._extract_domain_from_url(profile_payload["blog"])
            if blog_domain:
                dom_node = EntityNode(
                    entity_type=EntityType.DOMAIN,
                    value=blog_domain,
                    confidence=0.85,
                    attributes={"source_url": profile_payload["blog"]},
                    evidence_ids=[ev_profile.evidence_id],
                )
                nodes.append(dom_node)
                edges.append(
                    RelationshipEdge(
                        source_node_id=profile_node.node_id,
                        target_node_id=dom_node.node_id,
                        relation_type=RelationType.OWNS_DOMAIN,
                        weight=0.85,
                        confidence=0.85,
                        rationale=f"Website domain listed on GitHub profile '{login}'",
                        evidence_ids=[ev_profile.evidence_id],
                    )
                )

        # 2. Fetch public repositories
        repos_by_name: dict[str, EntityNode] = {}
        repos_url = f"https://api.github.com/users/{login}/repos"
        try:
            r_status, r_payload, r_ev, _ = await self.fetch_with_custody(
                url=repos_url,
                case_id=case_id,
                ledger=active_ledger,
                storage=storage,
                params={"per_page": 30, "sort": "updated"},
                headers=headers,
                notes=f"GitHub public repositories for '{login}'",
            )
            if r_status == 200 and r_ev is not None and isinstance(r_payload, list):
                evidence_items.append(r_ev)
                for repo in r_payload:
                    if not isinstance(repo, dict) or not repo.get("full_name"):
                        continue
                    full_name = str(repo["full_name"])
                    repo_node = EntityNode(
                        entity_type=EntityType.REPOSITORY,
                        value=f"github.com/{full_name}",
                        platform="GitHub",
                        confidence=0.95,
                        attributes={
                            "full_name": full_name,
                            "language": repo.get("language") or "",
                            "stars": repo.get("stargazers_count", 0),
                            "fork": bool(repo.get("fork", False)),
                        },
                        evidence_ids=[r_ev.evidence_id],
                    )
                    repos_by_name[full_name.lower()] = repo_node
                    nodes.append(repo_node)
                    edges.append(
                        RelationshipEdge(
                            source_node_id=profile_node.node_id,
                            target_node_id=repo_node.node_id,
                            relation_type=RelationType.OWNS_REPO,
                            weight=0.95,
                            confidence=0.95,
                            rationale=f"Owned GitHub repository '{full_name}'",
                            evidence_ids=[r_ev.evidence_id],
                        )
                    )
        except Exception as exc:
            errors.append(f"GitHub repos fetch failed: {type(exc).__name__}: {exc}")

        # 3. Fetch public events (PushEvent commit emails & timestamps)
        events_url = f"https://api.github.com/users/{login}/events/public"
        try:
            e_status, e_payload, e_ev, _ = await self.fetch_with_custody(
                url=events_url,
                case_id=case_id,
                ledger=active_ledger,
                storage=storage,
                params={"per_page": 30},
                headers=headers,
                notes=f"GitHub public events & commit intelligence for '{login}'",
            )
            if e_status == 200 and e_ev is not None and isinstance(e_payload, list):
                evidence_items.append(e_ev)
                for event in e_payload:
                    if not isinstance(event, dict):
                        continue
                    ev_ts = event.get("created_at")
                    if isinstance(ev_ts, str) and ev_ts.strip():
                        timestamps.append(ev_ts.strip())

                    repo_info = event.get("repo") or {}
                    repo_full_name = str(repo_info.get("name") or "").strip()
                    payload_block = event.get("payload") or {}
                    commits = payload_block.get("commits") or []

                    for commit in commits:
                        if not isinstance(commit, dict):
                            continue
                        c_ts = commit.get("timestamp")
                        if isinstance(c_ts, str) and c_ts.strip():
                            timestamps.append(c_ts.strip())
                        author = commit.get("author") or {}
                        c_email = author.get("email")
                        if isinstance(c_email, str) and c_email.strip():
                            _add_email_node(
                                c_email,
                                f"GitHub PushEvent commit ({repo_full_name or login})",
                                e_ev.evidence_id,
                                0.92,
                            )

                    if repo_full_name and repo_full_name.lower() not in repos_by_name:
                        ext_repo = EntityNode(
                            entity_type=EntityType.REPOSITORY,
                            value=f"github.com/{repo_full_name}",
                            platform="GitHub",
                            confidence=0.85,
                            evidence_ids=[e_ev.evidence_id],
                        )
                        repos_by_name[repo_full_name.lower()] = ext_repo
                        nodes.append(ext_repo)
                        edges.append(
                            RelationshipEdge(
                                source_node_id=profile_node.node_id,
                                target_node_id=ext_repo.node_id,
                                relation_type=RelationType.COMMITTED_TO,
                                weight=0.85,
                                confidence=0.85,
                                rationale=f"Public event activity observed on repository '{repo_full_name}'",
                                evidence_ids=[e_ev.evidence_id],
                            )
                        )
        except Exception as exc:
            errors.append(f"GitHub events fetch failed: {type(exc).__name__}: {exc}")

        profile_node.attributes["timestamps"] = sorted(set(timestamps))

        # 4. Fetch public SSH keys (https://github.com/<user>.keys)
        ssh_keys_url = f"https://github.com/{login}.keys"
        try:
            k_status, k_payload, k_ev, _ = await self.fetch_with_custody(
                url=ssh_keys_url,
                case_id=case_id,
                ledger=active_ledger,
                storage=storage,
                headers={"Accept": "text/plain"},
                notes=f"GitHub public SSH keys for '{login}'",
            )
            if k_status == 200 and k_ev is not None and isinstance(k_payload, str):
                key_lines = [line.strip() for line in k_payload.splitlines() if line.strip()]
                if key_lines:
                    evidence_items.append(k_ev)
                for key_line in key_lines:
                    parts = key_line.split()
                    key_type = parts[0] if parts else "ssh-key"
                    key_preview = f"{key_type} {parts[1][:32]}..." if len(parts) > 1 and len(parts[1]) > 32 else key_line
                    ssh_node = EntityNode(
                        entity_type=EntityType.SSH_KEY,
                        value=key_line,
                        label=f"SSH:{key_preview}",
                        platform="GitHub",
                        confidence=0.96,
                        attributes={"key_type": key_type},
                        evidence_ids=[k_ev.evidence_id],
                    )
                    nodes.append(ssh_node)
                    edges.append(
                        RelationshipEdge(
                            source_node_id=profile_node.node_id,
                            target_node_id=ssh_node.node_id,
                            relation_type=RelationType.USES_KEY,
                            weight=0.96,
                            confidence=0.96,
                            rationale=f"Public SSH key published at github.com/{login}.keys",
                            evidence_ids=[k_ev.evidence_id],
                        )
                    )
        except Exception as exc:
            errors.append(f"GitHub SSH keys fetch failed: {type(exc).__name__}: {exc}")

        # 5. Fetch public GPG/PGP keys
        gpg_url = f"https://api.github.com/users/{login}/gpg_keys"
        try:
            g_status, g_payload, g_ev, _ = await self.fetch_with_custody(
                url=gpg_url,
                case_id=case_id,
                ledger=active_ledger,
                storage=storage,
                headers=headers,
                notes=f"GitHub public GPG/PGP keys for '{login}'",
            )
            if g_status == 200 and g_ev is not None and isinstance(g_payload, list) and g_payload:
                evidence_items.append(g_ev)
                for gpg in g_payload:
                    if not isinstance(gpg, dict) or not gpg.get("key_id"):
                        continue
                    key_id = str(gpg["key_id"]).upper()
                    pgp_node = EntityNode(
                        entity_type=EntityType.PGP_KEY,
                        value=f"0x{key_id}" if not key_id.startswith("0X") else key_id,
                        platform="GitHub",
                        confidence=0.96,
                        attributes={
                            "primary_key_id": gpg.get("primary_key_id"),
                            "emails": [e.get("email") for e in (gpg.get("emails") or []) if isinstance(e, dict)],
                        },
                        evidence_ids=[g_ev.evidence_id],
                    )
                    nodes.append(pgp_node)
                    edges.append(
                        RelationshipEdge(
                            source_node_id=profile_node.node_id,
                            target_node_id=pgp_node.node_id,
                            relation_type=RelationType.USES_KEY,
                            weight=0.96,
                            confidence=0.96,
                            rationale=f"Public GPG/PGP key published by GitHub user '{login}'",
                            evidence_ids=[g_ev.evidence_id],
                        )
                    )
                    for email_entry in gpg.get("emails") or []:
                        if isinstance(email_entry, dict) and email_entry.get("email"):
                            _add_email_node(
                                str(email_entry["email"]),
                                f"GitHub GPG key {key_id}",
                                g_ev.evidence_id,
                                0.96,
                            )
        except Exception as exc:
            errors.append(f"GitHub GPG keys fetch failed: {type(exc).__name__}: {exc}")

        return CollectorResult(
            collector_name=self.name,
            query=login,
            nodes=nodes,
            edges=edges,
            evidence_items=evidence_items,
            errors=errors,
        )
