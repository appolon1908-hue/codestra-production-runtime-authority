from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "validate_immutable_candidate_matrix_final.py"
spec = importlib.util.spec_from_file_location("matrix_validator", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
SCHEMA = json.loads((ROOT / "config" / "immutable-workload-evidence.v1.schema.json").read_text())


def workload(name: str, marker: str) -> dict:
    digest = f"sha256:{marker * 64}"
    image = f"ghcr.io/codestra/{name}@{digest}"
    rollback_marker = "f" if marker != "f" else "e"
    source_sha = marker * 40
    repository = f"codestra/{name}"
    return {
        "schema_version": 1,
        "workload_id": name,
        "repository": repository,
        "protected_source_sha": source_sha,
        "image": image,
        "image_digest": digest,
        "signature": {"status": "PASS", "reference": f"oci://signature/{name}/{marker * 16}", "subject_image": image},
        "sbom": {"status": "PASS", "reference": f"oci://sbom/{name}/{marker * 16}", "sha256": marker * 64},
        "provenance": {
            "status": "PASS", "reference": f"oci://provenance/{name}/{marker * 16}",
            "subject_image": image, "source_repository": repository, "source_sha": source_sha,
        },
        "vulnerability_scan": {
            "status": "PASS", "critical": 0, "high": 0,
            "reference": f"evidence:scan/{name}/{marker * 16}",
        },
        "configuration_sha256": marker * 64,
        "rollback_digest": f"sha256:{rollback_marker * 64}",
        "exact_head_ci": "PASS",
        "independent_review": "PASS",
        "staging_certification": "PASS",
        "runtime_identity": {"source_sha_readback": source_sha, "image_digest_readback": digest},
        "safety": {
            "business_writes": False, "communications_delivery": False,
            "provider_effects": False, "financial_or_trading_mutation": False,
        },
    }


class ImmutableMatrixTests(unittest.TestCase):
    def good(self) -> dict:
        return {
            "schema": "codestra.immutable-candidate-matrix.v1",
            "captured_at": "2026-09-03T16:00:00Z",
            "production_changed": False,
            "deployment_authorized": True,
            "candidates": {"alpha": workload("alpha", "a"), "beta": workload("beta", "b")},
        }

    def validate(self, value: dict) -> dict:
        return module.validate(value, SCHEMA, expected=2, require_authorized=True)

    def test_complete_matrix_passes(self) -> None:
        result = self.validate(self.good())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["finding_count"], 0)

    def test_exact_workload_count_required(self) -> None:
        value = self.good(); value["candidates"].pop("beta")
        self.assertIn("WORKLOAD_COUNT", {item["code"] for item in self.validate(value)["findings"]})

    def test_root_denial_cannot_be_overridden_by_nested_authorization(self) -> None:
        value = self.good()
        value["deployment_authorized"] = False
        value["candidates"]["alpha"]["deployment_authorized"] = True
        result = self.validate(value)
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("DEPLOYMENT_AUTHORIZATION", codes)
        self.assertIn("DEPLOYMENT_AUTHORIZATION_STRUCTURE", codes)
        self.assertFalse(result["deployment_authorized"])

    def test_unknown_source_is_rejected(self) -> None:
        value = self.good(); value["candidates"]["alpha"]["protected_source_sha"] = "UNKNOWN"
        codes = {item["code"] for item in self.validate(value)["findings"]}
        self.assertIn("UNRESOLVED_VALUE", codes)
        self.assertIn("WORKLOAD_SCHEMA", codes)

    def test_mutable_latest_is_rejected(self) -> None:
        value = self.good(); value["candidates"]["alpha"]["image"] = "ghcr.io/codestra/alpha:latest"
        codes = {item["code"] for item in self.validate(value)["findings"]}
        self.assertIn("MUTABLE_IMAGE", codes)
        self.assertIn("WORKLOAD_SCHEMA", codes)

    def test_image_digest_must_match(self) -> None:
        value = self.good(); value["candidates"]["alpha"]["image_digest"] = "sha256:" + "c" * 64
        codes = {item["code"] for item in self.validate(value)["findings"]}
        self.assertIn("IMAGE_DIGEST_MISMATCH", codes)
        self.assertIn("RUNTIME_DIGEST_MISMATCH", codes)

    def test_complete_schema_is_required(self) -> None:
        value = self.good()
        for field in ("configuration_sha256", "exact_head_ci", "independent_review", "staging_certification"):
            del value["candidates"]["alpha"][field]
        self.assertIn("WORKLOAD_SCHEMA", {item["code"] for item in self.validate(value)["findings"]})

    def test_runtime_readbacks_must_match_candidate(self) -> None:
        value = self.good()
        value["candidates"]["alpha"]["runtime_identity"]["source_sha_readback"] = "c" * 40
        value["candidates"]["alpha"]["runtime_identity"]["image_digest_readback"] = "sha256:" + "c" * 64
        codes = {item["code"] for item in self.validate(value)["findings"]}
        self.assertIn("RUNTIME_SOURCE_MISMATCH", codes)
        self.assertIn("RUNTIME_DIGEST_MISMATCH", codes)

    def test_signature_and_provenance_subjects_are_bound(self) -> None:
        value = self.good()
        value["candidates"]["alpha"]["signature"]["subject_image"] = value["candidates"]["beta"]["image"]
        value["candidates"]["alpha"]["provenance"]["source_sha"] = "c" * 40
        codes = {item["code"] for item in self.validate(value)["findings"]}
        self.assertIn("SIGNATURE_SUBJECT_MISMATCH", codes)
        self.assertIn("PROVENANCE_SOURCE_MISMATCH", codes)

    def test_noop_rollback_is_rejected(self) -> None:
        value = self.good()
        value["candidates"]["alpha"]["rollback_digest"] = value["candidates"]["alpha"]["image_digest"]
        self.assertIn("ROLLBACK_NOOP", {item["code"] for item in self.validate(value)["findings"]})


if __name__ == "__main__":
    unittest.main()
