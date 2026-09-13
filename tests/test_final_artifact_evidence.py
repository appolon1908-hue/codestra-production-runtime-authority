from __future__ import annotations

import importlib.util
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "validate_final_artifact_evidence.py"
spec = importlib.util.spec_from_file_location("artifact_validator", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

NOW = datetime(2026, 9, 3, 16, 0, tzinfo=timezone.utc)


def policy() -> dict:
    return {
        "expected_artifacts": 2,
        "allowed_architectures": ["linux/amd64", "linux/arm64"],
        "required_signature_issuer": "https://token.actions.githubusercontent.com",
        "required_certificate_identity_prefix": "https://github.com/",
        "required_provenance_predicate": "https://slsa.dev/provenance/v1",
        "allowed_sbom_formats": ["spdx-json", "cyclonedx-json"],
        "maximum_vulnerability_database_age_hours": 168,
        "maximum_critical_vulnerabilities": 0,
        "maximum_high_vulnerabilities": 0,
    }


def artifact(index: int, marker: str) -> dict:
    digest = "sha256:" + marker * 64
    rollback = "sha256:" + ("f" if marker != "f" else "e") * 64
    name = f"workload-{index:02d}"
    return {
        "workload_id": name,
        "repository": f"example/{name}",
        "source_sha": marker * 40,
        "build_run": f"https://github.com/example/{name}/actions/runs/{index + 100}",
        "image": f"ghcr.io/example/{name}@{digest}",
        "image_digest": digest,
        "architectures": ["linux/amd64"],
        "configuration_sha256": marker * 64,
        "signature": {
            "status": "PASS",
            "subject_image": f"ghcr.io/example/{name}@{digest}",
            "certificate_identity": f"https://github.com/example/{name}/.github/workflows/release.yml@refs/heads/production",
            "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
            "bundle_ref": f"oci://signature/{name}/{marker * 16}",
        },
        "sbom": {
            "status": "PASS",
            "format": "spdx-json",
            "reference": f"oci://sbom/{name}/{marker * 16}",
            "sha256": marker * 64,
        },
        "provenance": {
            "status": "PASS",
            "subject_image": f"ghcr.io/example/{name}@{digest}",
            "source_repository": f"example/{name}",
            "source_sha": marker * 40,
            "predicate_type": "https://slsa.dev/provenance/v1",
            "reference": f"oci://provenance/{name}/{marker * 16}",
        },
        "vulnerability_scan": {
            "status": "PASS",
            "scanner": "trivy-verified",
            "database_updated_at": "2026-09-03T12:00:00Z",
            "critical": 0,
            "high": 0,
            "reference": f"evidence:scan/{name}/{marker * 16}",
        },
        "secret_scan": "PASS",
        "dependency_audit": "PASS",
        "license_review": "PASS",
        "attestation_verification": "PASS",
        "rollback_digest": rollback,
        "evidence_ref": f"evidence:artifact/{name}/{marker * 16}",
    }


def evidence() -> dict:
    return {
        "schema_version": 1,
        "release_id": "release-20260903",
        "artifacts": [artifact(0, "a"), artifact(1, "b")],
        "summary": {
            "expected": 2,
            "observed": 2,
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 0,
            "unsigned_artifacts": 0,
            "missing_sboms": 0,
            "missing_provenance": 0,
            "mutable_images": 0,
        },
        "safety": {
            "deployment_performed": False,
            "business_writes": False,
            "communications_delivery": False,
            "provider_effects": False,
            "financial_or_trading_mutation": False,
        },
    }


def matrix(value: dict) -> dict:
    candidates = {}
    for item in value["artifacts"]:
        candidates[item["workload_id"]] = {
            "schema_version": 1,
            "workload_id": item["workload_id"],
            "repository": item["repository"],
            "protected_source_sha": item["source_sha"],
            "image": item["image"],
            "image_digest": item["image_digest"],
            "signature": {
                "status": "PASS",
                "reference": item["signature"]["bundle_ref"],
                "subject_image": item["signature"]["subject_image"],
            },
            "sbom": {
                "status": "PASS",
                "reference": item["sbom"]["reference"],
                "sha256": item["sbom"]["sha256"],
            },
            "provenance": {
                "status": "PASS",
                "reference": item["provenance"]["reference"],
                "subject_image": item["provenance"]["subject_image"],
                "source_repository": item["provenance"]["source_repository"],
                "source_sha": item["provenance"]["source_sha"],
            },
            "vulnerability_scan": {
                "status": "PASS",
                "critical": 0,
                "high": 0,
                "reference": item["vulnerability_scan"]["reference"],
            },
            "configuration_sha256": item["configuration_sha256"],
            "rollback_digest": item["rollback_digest"],
            "exact_head_ci": "PASS",
            "independent_review": "PASS",
            "staging_certification": "PASS",
            "runtime_identity": {
                "source_sha_readback": item["source_sha"],
                "image_digest_readback": item["image_digest"],
            },
            "safety": {
                "business_writes": False,
                "communications_delivery": False,
                "provider_effects": False,
                "financial_or_trading_mutation": False,
            },
        }
    return {
        "schema": "codestra.immutable-candidate-matrix.v1",
        "captured_at": "2026-09-03T16:00:00Z",
        "production_changed": False,
        "deployment_authorized": True,
        "candidates": candidates,
    }


class ArtifactEvidenceTests(unittest.TestCase):
    def validate(self, value: dict, matrix_value: dict | None = None) -> dict:
        return module.validate(
            value,
            policy(),
            matrix=matrix_value or matrix(value),
            matrix_schema=module.load_json(ROOT / "config" / "immutable-workload-evidence.v1.schema.json"),
            authority_sha="d" * 40,
            now=NOW,
        )

    def test_complete_evidence_passes(self) -> None:
        result = self.validate(evidence())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(len(result["artifacts"]), 2)

    def test_exact_count_required(self) -> None:
        value = evidence(); value["artifacts"].pop()
        with self.assertRaisesRegex(module.ArtifactError, "exactly 2"):
            self.validate(value)

    def test_mutable_image_rejected(self) -> None:
        value = evidence(); value["artifacts"][0]["image"] = "ghcr.io/example/workload-00:latest"
        with self.assertRaisesRegex(module.ArtifactError, "repository@sha256"):
            self.validate(value)

    def test_digest_mismatch_rejected(self) -> None:
        value = evidence(); value["artifacts"][0]["image_digest"] = "sha256:" + "c" * 64
        with self.assertRaisesRegex(module.ArtifactError, "disagree"):
            self.validate(value)

    def test_unapproved_signature_issuer_rejected(self) -> None:
        value = evidence(); value["artifacts"][0]["signature"]["certificate_oidc_issuer"] = "https://issuer.invalid"
        with self.assertRaisesRegex(module.ArtifactError, "approved issuer"):
            self.validate(value)

    def test_missing_sbom_rejected(self) -> None:
        value = evidence(); value["artifacts"][0]["sbom"]["status"] = "PENDING"
        with self.assertRaises(module.ArtifactError):
            self.validate(value)

    def test_stale_vulnerability_database_rejected(self) -> None:
        value = evidence(); value["artifacts"][0]["vulnerability_scan"]["database_updated_at"] = "2026-08-20T00:00:00Z"
        with self.assertRaisesRegex(module.ArtifactError, "stale"):
            self.validate(value)

    def test_high_vulnerability_rejected(self) -> None:
        value = evidence(); value["artifacts"][0]["vulnerability_scan"]["high"] = 1
        with self.assertRaisesRegex(module.ArtifactError, "exceeds policy"):
            self.validate(value)

    def test_noop_rollback_rejected(self) -> None:
        value = evidence(); value["artifacts"][0]["rollback_digest"] = value["artifacts"][0]["image_digest"]
        with self.assertRaisesRegex(module.ArtifactError, "must differ"):
            self.validate(value)

    def test_safety_effect_rejected(self) -> None:
        value = evidence(); value["safety"]["deployment_performed"] = True
        with self.assertRaisesRegex(module.ArtifactError, "must remain false"):
            self.validate(value)

    def test_stale_source_is_rejected_against_matrix(self) -> None:
        value = evidence()
        matrix_value = matrix(value)
        value["artifacts"][0]["source_sha"] = "c" * 40
        value["artifacts"][0]["provenance"]["source_sha"] = "c" * 40
        with self.assertRaisesRegex(module.ArtifactError, "source_sha differs"):
            self.validate(value, matrix_value)

    def test_configuration_is_rejected_against_matrix(self) -> None:
        value = evidence()
        matrix_value = matrix(value)
        value["artifacts"][0]["configuration_sha256"] = "c" * 64
        with self.assertRaisesRegex(module.ArtifactError, "configuration_sha256 differs"):
            self.validate(value, matrix_value)

    def test_signature_subject_is_bound(self) -> None:
        value = evidence()
        value["artifacts"][0]["signature"]["subject_image"] = value["artifacts"][1]["image"]
        with self.assertRaisesRegex(module.ArtifactError, "subject_image differs"):
            self.validate(value)

    def test_unauthorized_matrix_is_rejected(self) -> None:
        value = evidence()
        matrix_value = matrix(value)
        matrix_value["deployment_authorized"] = False
        with self.assertRaisesRegex(module.ArtifactError, "matrix is blocked"):
            self.validate(value, matrix_value)


if __name__ == "__main__":
    unittest.main()
