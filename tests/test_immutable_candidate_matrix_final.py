from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "validate_immutable_candidate_matrix_final.py"
spec = importlib.util.spec_from_file_location("matrix_validator", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def workload(name: str, marker: str) -> dict:
    digest = f"sha256:{marker * 64}"
    rollback_marker = "f" if marker != "f" else "e"
    return {
        "workload_id": name,
        "repository": f"codestra/{name}",
        "source_sha": marker * 40,
        "image": f"ghcr.io/codestra/{name}@{digest}",
        "image_digest": digest,
        "signature": f"oci://signature/{name}/{marker * 16}",
        "sbom": f"oci://sbom/{name}/{marker * 16}",
        "provenance": f"oci://provenance/{name}/{marker * 16}",
        "rollback_digest": f"sha256:{rollback_marker * 64}",
    }


class ImmutableMatrixTests(unittest.TestCase):
    def good(self) -> dict:
        return {
            "deployment_authorized": True,
            "workloads": [workload("alpha", "a"), workload("beta", "b")],
        }

    def test_complete_matrix_passes(self) -> None:
        result = module.validate(self.good(), expected=2, require_authorized=True)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["finding_count"], 0)

    def test_exact_workload_count_required(self) -> None:
        value = self.good()
        value["workloads"].pop()
        result = module.validate(value, expected=2, require_authorized=True)
        self.assertIn("WORKLOAD_COUNT", {item["code"] for item in result["findings"]})

    def test_unknown_source_is_rejected(self) -> None:
        value = self.good()
        value["workloads"][0]["source_sha"] = "UNKNOWN"
        result = module.validate(value, expected=2, require_authorized=True)
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("UNRESOLVED_VALUE", codes)
        self.assertIn("SOURCE_SHA", codes)

    def test_mutable_latest_is_rejected(self) -> None:
        value = self.good()
        value["workloads"][0]["image"] = "ghcr.io/codestra/alpha:latest"
        result = module.validate(value, expected=2, require_authorized=True)
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("MUTABLE_IMAGE", codes)
        self.assertIn("IMAGE", codes)

    def test_image_digest_must_match(self) -> None:
        value = self.good()
        value["workloads"][0]["image_digest"] = "sha256:" + "c" * 64
        result = module.validate(value, expected=2, require_authorized=True)
        self.assertIn("IMAGE_DIGEST_MISMATCH", {item["code"] for item in result["findings"]})

    def test_supply_chain_evidence_is_required(self) -> None:
        value = self.good()
        value["workloads"][0]["signature"] = "PENDING"
        value["workloads"][0]["sbom"] = None
        value["workloads"][0]["provenance"] = "UNVERIFIED"
        result = module.validate(value, expected=2, require_authorized=True)
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("SIGNATURE", codes)
        self.assertIn("SBOM", codes)
        self.assertIn("PROVENANCE", codes)

    def test_noop_rollback_is_rejected(self) -> None:
        value = self.good()
        value["workloads"][0]["rollback_digest"] = value["workloads"][0]["image_digest"]
        result = module.validate(value, expected=2, require_authorized=True)
        self.assertIn("ROLLBACK_NOOP", {item["code"] for item in result["findings"]})

    def test_deployment_authorization_is_required(self) -> None:
        value = self.good()
        value["deployment_authorized"] = False
        result = module.validate(value, expected=2, require_authorized=True)
        self.assertIn("DEPLOYMENT_AUTHORIZATION", {item["code"] for item in result["findings"]})


if __name__ == "__main__":
    unittest.main()
