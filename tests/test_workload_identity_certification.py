from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "validate_workload_identity_certification.py"
spec = importlib.util.spec_from_file_location("identity_validator", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

REQUIRED_TESTS = [
    "authenticated_positive",
    "wrong_audience_denied",
    "wrong_subject_denied",
    "wrong_business_denied",
    "wrong_application_denied",
    "wrong_environment_denied",
    "expired_credential_denied",
    "revoked_credential_denied",
    "cross_business_secret_denied",
]


def policy() -> dict:
    return {
        "expected_identities": 2,
        "allowed_authentication_methods": [
            "jwt-workload-identity", "mtls-client-certificate", "oidc-client-credentials"
        ],
        "maximum_token_ttl_seconds": 900,
        "maximum_certificate_ttl_seconds": 3600,
        "required_tests": REQUIRED_TESTS,
    }


def identity(index: int, marker: str) -> dict:
    workload = f"workload-{index:02d}"
    business = f"business-{index:02d}"
    application = f"application-{index:02d}"
    environment = "staging"
    subject = f"spiffe://codestra/{business}/{application}/{environment}/{workload}"
    audiences = [f"audience-{index:02d}"]
    return {
        "workload_id": workload,
        "repository": f"example/{workload}",
        "source_sha": marker * 40,
        "business": business,
        "application": application,
        "environment": environment,
        "subject": subject,
        "audiences": audiences,
        "authentication_method": "jwt-workload-identity",
        "credential_ttl_seconds": 600,
        "policy_ref": f"evidence:policy/{workload}/{marker * 16}",
        "policy_sha256": marker * 64,
        "allowed_secret_prefixes": [f"kv-{business}/data/{application}/{environment}/runtime/"],
        "denied_capabilities": [
            "root", "sudo", "cross-business", "provider-effect",
            "communications-delivery", "financial-trading"
        ],
        "identity_readback": {
            "subject": subject,
            "audiences": audiences,
            "business": business,
            "application": application,
            "environment": environment,
            "ttl_seconds": 590,
        },
        "tests": {name: "PASS" for name in REQUIRED_TESTS},
        "business_write_authority": False,
        "communications_delivery_authority": False,
        "provider_effect_authority": False,
        "financial_or_trading_mutation_authority": False,
        "evidence_ref": f"evidence:identity/{workload}/{marker * 16}",
    }


def evidence() -> dict:
    return {
        "schema_version": 1,
        "release_id": "release-20260903",
        "identities": [identity(0, "a"), identity(1, "b")],
        "summary": {
            "expected": 2,
            "observed": 2,
            "shared_wildcard_identities": 0,
            "long_lived_credentials": 0,
            "cross_business_leaks": 0,
            "expired_credential_failures": 0,
            "revocation_failures": 0,
            "wrong_audience_failures": 0,
            "forbidden_authority_grants": 0,
        },
        "safety": {
            "credentials_recorded": False,
            "identities_issued_by_validator": False,
            "business_writes": False,
            "communications_delivery": False,
            "provider_effects": False,
            "financial_or_trading_mutation": False,
        },
    }


class WorkloadIdentityTests(unittest.TestCase):
    def test_complete_identities_pass(self) -> None:
        result = module.validate(evidence(), policy())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(len(result["identities"]), 2)

    def test_exact_count_required(self) -> None:
        value = evidence(); value["identities"].pop()
        with self.assertRaisesRegex(module.IdentityError, "exactly 2"):
            module.validate(value, policy())

    def test_wildcard_subject_rejected(self) -> None:
        value = evidence(); value["identities"][0]["subject"] += "/*"
        with self.assertRaisesRegex(module.IdentityError, "wildcarded"):
            module.validate(value, policy())

    def test_wildcard_audience_rejected(self) -> None:
        value = evidence(); value["identities"][0]["audiences"] = ["*"]
        with self.assertRaisesRegex(module.IdentityError, "wildcard audience"):
            module.validate(value, policy())

    def test_long_lived_token_rejected(self) -> None:
        value = evidence(); value["identities"][0]["credential_ttl_seconds"] = 901
        with self.assertRaisesRegex(module.IdentityError, "exceeds policy"):
            module.validate(value, policy())

    def test_secret_prefix_escape_rejected(self) -> None:
        value = evidence(); value["identities"][0]["allowed_secret_prefixes"] = ["kv-*/data/*"]
        with self.assertRaisesRegex(module.IdentityError, "escapes"):
            module.validate(value, policy())

    def test_required_denial_rejected_when_missing(self) -> None:
        value = evidence(); value["identities"][0]["denied_capabilities"].remove("cross-business")
        with self.assertRaisesRegex(module.IdentityError, "omits required denial"):
            module.validate(value, policy())

    def test_identity_readback_must_match(self) -> None:
        value = evidence(); value["identities"][0]["identity_readback"]["business"] = "other-business"
        with self.assertRaisesRegex(module.IdentityError, "does not match"):
            module.validate(value, policy())

    def test_revocation_test_must_pass(self) -> None:
        value = evidence(); value["identities"][0]["tests"]["revoked_credential_denied"] = "FAIL"
        with self.assertRaisesRegex(module.IdentityError, "failed or incomplete"):
            module.validate(value, policy())

    def test_forbidden_authority_rejected(self) -> None:
        value = evidence(); value["identities"][0]["provider_effect_authority"] = True
        with self.assertRaisesRegex(module.IdentityError, "grants forbidden"):
            module.validate(value, policy())

    def test_duplicate_subject_rejected(self) -> None:
        value = evidence(); value["identities"][1]["subject"] = value["identities"][0]["subject"]
        value["identities"][1]["identity_readback"]["subject"] = value["identities"][0]["subject"]
        with self.assertRaisesRegex(module.IdentityError, "subjects must be unique"):
            module.validate(value, policy())

    def test_credential_value_field_rejected(self) -> None:
        value = evidence(); value["identities"][0]["token_value"] = "not-a-real-token"
        with self.assertRaisesRegex(module.IdentityError, "secret value field"):
            module.validate(value, policy())


if __name__ == "__main__":
    unittest.main()
