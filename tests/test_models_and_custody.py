"""Unit tests for Task 1: Core Ontology & OSINT Pilot Chain-of-Custody Engine."""

from __future__ import annotations

import unittest

from pydantic import ValidationError

from omnisint.core.custody import (
    GENESIS_CHAIN_HASH,
    CustodyLedger,
    CustodySigner,
    compute_sha256,
)
from omnisint.core.models import (
    Case,
    CaseStatus,
    EntityNode,
    EntityType,
    HierarchyTreeNode,
    PersonaCluster,
    RelationshipEdge,
    RelationType,
)


class TestModelsAndCustody(unittest.TestCase):
    """Test suite for OmniSINT core models and cryptographic chain of custody."""

    def test_entity_node_defaults_and_canonical_key(self) -> None:
        node = EntityNode(
            entity_type=EntityType.SOCIAL_PROFILE,
            value="Alex_Sec",
            platform="GitHub",
            entropy_score=3.12,
            rarity_score=0.78,
        )
        self.assertEqual(node.label, "GitHub:Alex_Sec")
        self.assertEqual(node.canonical_key, "social_profile:github:alex_sec")
        self.assertTrue(0.0 <= node.confidence <= 1.0)

    def test_relationship_edge_prevents_self_loop(self) -> None:
        with self.assertRaises(ValidationError):
            RelationshipEdge(
                source_node_id="node-1",
                target_node_id="node-1",
                relation_type=RelationType.SIMILAR_HANDLE,
            )

    def test_hierarchy_tree_and_persona_cluster_serialization(self) -> None:
        leaf = HierarchyTreeNode(
            node_id="n-repo-1",
            label="github.com/alex/omnisint",
            category="Repositories",
            entity_type=EntityType.REPOSITORY,
            confidence=0.95,
        )
        root = HierarchyTreeNode(
            node_id="n-root",
            label="Persona #1: Alex (Security Researcher)",
            category="Root Persona",
            entity_type=EntityType.PERSON,
            children=[leaf],
        )
        persona = PersonaCluster(
            persona_label="Alex (Security Researcher)",
            primary_handle="alex_sec",
            confidence_score=0.92,
            avg_handle_entropy=3.45,
            inferred_timezone="UTC+05:30",
            node_ids=["n-root", "n-repo-1"],
            hierarchy_tree=root,
        )
        case = Case(
            title="Target Footprint Investigation",
            target_query="alex_sec",
            personas=[persona],
        )
        self.assertEqual(case.status, CaseStatus.OPEN)
        self.assertEqual(len(case.personas), 1)
        self.assertIsNotNone(case.personas[0].hierarchy_tree)
        assert case.personas[0].hierarchy_tree is not None
        self.assertEqual(
            case.personas[0].hierarchy_tree.children[0].label,
            "github.com/alex/omnisint",
        )

    def test_custody_ledger_hash_chaining_and_verification(self) -> None:
        ledger = CustodyLedger(case_id="case-001")
        self.assertEqual(ledger.head_chain_hash, GENESIS_CHAIN_HASH)

        ev1 = ledger.record_evidence(
            collector_name="github_collector",
            source_uri="https://api.github.com/users/alex_sec",
            raw_payload={"login": "alex_sec", "id": 1001, "public_repos": 12},
            notes="GitHub profile JSON response",
        )
        ev2 = ledger.record_evidence(
            collector_name="domain_ct_collector",
            source_uri="https://crt.sh/?q=alexsec.io&output=json",
            raw_payload='[{"common_name":"api.alexsec.io"}]',
            notes="crt.sh certificate transparency log",
        )

        self.assertEqual(ev1.prev_chain_hash, GENESIS_CHAIN_HASH)
        self.assertEqual(ev2.prev_chain_hash, ev1.chain_hash)
        self.assertEqual(ledger.head_chain_hash, ev2.chain_hash)
        self.assertEqual(len(ledger.audit_log), 2)

        is_valid, violations = ledger.verify_chain()
        self.assertTrue(is_valid)
        self.assertEqual(violations, [])

    def test_custody_ledger_detects_tampering(self) -> None:
        ledger = CustodyLedger(case_id="case-tamper")
        ev1 = ledger.record_evidence(
            collector_name="username_collector",
            source_uri="https://reddit.com/user/alex_sec/about.json",
            raw_payload={"name": "alex_sec", "karma": 450},
        )
        ledger.record_evidence(
            collector_name="threat_intel",
            source_uri="https://www.virustotal.com/api/v3/domains/alexsec.io",
            raw_payload={"reputation": 0},
        )

        # Simulate tampering with the raw payload of evidence item 1
        assert isinstance(ev1.raw_payload, dict)
        ev1.raw_payload["karma"] = 999999

        self.assertFalse(ledger.verify_item(ev1))
        is_valid, violations = ledger.verify_chain()
        self.assertFalse(is_valid)
        self.assertEqual(len(violations), 1)
        self.assertIn(ev1.evidence_id, violations[0])

    def test_compute_sha256_canonical_json_key_order(self) -> None:
        payload_a = {"b": 2, "a": 1, "nested": {"z": 9, "y": 8}}
        payload_b = {"nested": {"y": 8, "z": 9}, "a": 1, "b": 2}
        self.assertEqual(compute_sha256(payload_a), compute_sha256(payload_b))

    def test_custody_binds_evidence_id_case_id_kind_and_list_payloads(self) -> None:
        ledger = CustodyLedger(case_id="case-binding-1")
        ev_list = ledger.record_evidence(
            collector_name="domain_ct_collector",
            source_uri="https://crt.sh/?q=alexsec.io&output=json",
            raw_payload=[{"common_name": "api.alexsec.io"}],
        )
        self.assertIsInstance(ev_list.raw_payload, list)
        self.assertTrue(ledger.verify_item(ev_list))

        # Swapping evidence_id or case_id must fail verification
        tampered_id = ev_list.model_copy(update={"evidence_id": "forged-ev-id"})
        self.assertFalse(ledger.verify_item(tampered_id))
        tampered_case = ev_list.model_copy(update={"case_id": "other-case"})
        self.assertFalse(ledger.verify_item(tampered_case))

        # Raw JSON string vs parsed dict must have distinct chain hashes via payload_kind
        ev_dict = ledger.record_evidence(
            collector_name="test",
            source_uri="https://example.org/a",
            raw_payload={"a": 1},
        )
        ledger2 = CustodyLedger(case_id="case-binding-2")
        ev_str = ledger2.record_evidence(
            collector_name="test",
            source_uri="https://example.org/a",
            raw_payload='{"a":1}',
        )
        self.assertEqual(ev_dict.sha256_hash, ev_str.sha256_hash)
        self.assertNotEqual(ev_dict.chain_hash, ev_str.chain_hash)

    def test_custody_signer_ed25519_signs_and_detects_chain_rewrite(self) -> None:
        ledger = CustodyLedger(case_id="case-signed")
        ledger.record_evidence(
            collector_name="github_collector",
            source_uri="https://api.github.com/users/alex_sec",
            raw_payload={"login": "alex_sec"},
        )
        signer = CustodySigner()
        sig_hex = signer.sign_ledger(ledger)
        pub_hex = signer.public_key_hex

        self.assertTrue(CustodySigner.verify_signature(ledger, sig_hex, pub_hex))

        # Even if an attacker rewrites the entire chain consistently, signature verification fails
        rebuilt = CustodyLedger(case_id="case-signed")
        rebuilt.record_evidence(
            collector_name="github_collector",
            source_uri="https://api.github.com/users/alex_sec",
            raw_payload={"login": "attacker_rewrite"},
        )
        self.assertTrue(rebuilt.verify_chain()[0])
        self.assertFalse(CustodySigner.verify_signature(rebuilt, sig_hex, pub_hex))


if __name__ == "__main__":
    unittest.main()
