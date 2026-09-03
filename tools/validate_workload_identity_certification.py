#!/usr/bin/env python3
"""Validate 64 short-lived least-privilege workload identities.

The validator consumes sanitized staging evidence. It cannot authenticate, issue,
renew, revoke, or read a credential and cannot contact OpenBao or Keycloak.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "config" / "workload-identity-certification-policy.v1.json"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SUBJECT_RE = re.compile(r"^[a-zA-Z0-9:/._-]{4,255}$")
FORBIDDEN = (
    "UNKNOWN", "PENDING", "NOT_RUN", "NOT_STARTED", "NONE", "TBD", "TODO",
    "REPLACE_ME", "UNVERIFIED", "UNRESOLVED", "LOCAL_ONLY", "PLACEHOLDER"
)
SECRET_KEYS = (
    "password", "private_key", "secret_value", "access_token", "refresh_token",
    "authorization_value", "cookie_value", "client_secret", "ssh_key", "token_value",
    "certificate_pem", "jwt_value"
)
REQUIRED_DENIALS = {
    "root", "sudo", "cross-business", "provider-effect", "communications-delivery",
    "financial-trading"
}


class IdentityError(RuntimeError):
    """Malformed or failing workload identity evidence."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IdentityError(f"cannot parse JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise IdentityError(f"JSON root must be an object: {path}")
    return value


def walk(value: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{path}[{index}]")


def reject_sensitive_or_unresolved(value: Any) -> None:
    for path, child in walk(value):
        if isinstance(child, str):
            upper = child.upper()
            if any(marker == upper or marker in upper for marker in FORBIDDEN):
                raise IdentityError(f"unresolved value at {path}")
            if "-----BEGIN" in child or upper.startswith("BEARER "):
                raise IdentityError(f"credential-shaped value at {path}")
        if isinstance(child, dict):
            for key, item in child.items():
                normalized = str(key).lower().replace("-", "_")
                if any(fragment in normalized for fragment in SECRET_KEYS):
                    if item not in (None, False, "") and not normalized.endswith("_ref"):
                        raise IdentityError(f"secret value field is prohibited at {path}.{key}")


def require_reference(value: Any, path: str) -> str:
    if not isinstance(value, str) or len(value.strip()) < 8:
        raise IdentityError(f"{path} must be a non-empty evidence reference")
    if any(marker in value.upper() for marker in FORBIDDEN):
        raise IdentityError(f"{path} is unresolved")
    parsed = urlsplit(value)
    if parsed.scheme in {"http", "https"} and (parsed.username or parsed.password):
        raise IdentityError(f"{path} must not embed credentials")
    return value


def require_id(value: Any, path: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise IdentityError(f"{path} is invalid")
    return value


def require_nonempty_list(value: Any, path: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise IdentityError(f"{path} must be a non-empty list")
    if len(value) != len(set(value)) or not all(isinstance(item, str) and item for item in value):
        raise IdentityError(f"{path} must contain unique non-empty strings")
    return value


def validate_identity(value: Any, index: int, policy: dict[str, Any]) -> dict[str, Any]:
    path = f"identities[{index}]"
    required = {
        "workload_id", "repository", "source_sha", "business", "application",
        "environment", "subject", "audiences", "authentication_method",
        "credential_ttl_seconds", "policy_ref", "policy_sha256",
        "allowed_secret_prefixes", "denied_capabilities", "identity_readback",
        "tests", "business_write_authority", "communications_delivery_authority",
        "provider_effect_authority", "financial_or_trading_mutation_authority",
        "evidence_ref"
    }
    if not isinstance(value, dict) or set(value) != required:
        raise IdentityError(f"{path} fields are incomplete or unexpected")
    workload = require_id(value.get("workload_id"), f"{path}.workload_id")
    repository = value.get("repository")
    if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository):
        raise IdentityError(f"{path}.repository is invalid")
    source_sha = value.get("source_sha")
    if not isinstance(source_sha, str) or not SHA_RE.fullmatch(source_sha):
        raise IdentityError(f"{path}.source_sha is invalid")
    business = require_id(value.get("business"), f"{path}.business")
    application = require_id(value.get("application"), f"{path}.application")
    environment = require_id(value.get("environment"), f"{path}.environment")
    subject = value.get("subject")
    if not isinstance(subject, str) or not SUBJECT_RE.fullmatch(subject) or "*" in subject:
        raise IdentityError(f"{path}.subject is invalid or wildcarded")
    audiences = require_nonempty_list(value.get("audiences"), f"{path}.audiences")
    if any("*" in audience or not ID_RE.fullmatch(audience) for audience in audiences):
        raise IdentityError(f"{path}.audiences contains an invalid or wildcard audience")
    method = value.get("authentication_method")
    if method not in set(policy["allowed_authentication_methods"]):
        raise IdentityError(f"{path}.authentication_method is not approved")
    ttl = value.get("credential_ttl_seconds")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
        raise IdentityError(f"{path}.credential_ttl_seconds must be positive")
    maximum = (
        policy["maximum_certificate_ttl_seconds"]
        if method == "mtls-client-certificate"
        else policy["maximum_token_ttl_seconds"]
    )
    if ttl > maximum:
        raise IdentityError(f"{path}.credential_ttl_seconds exceeds policy")
    require_reference(value.get("policy_ref"), f"{path}.policy_ref")
    policy_hash = value.get("policy_sha256")
    if not isinstance(policy_hash, str) or not HEX64_RE.fullmatch(policy_hash):
        raise IdentityError(f"{path}.policy_sha256 is invalid")

    prefixes = require_nonempty_list(value.get("allowed_secret_prefixes"), f"{path}.allowed_secret_prefixes")
    expected_prefix = f"kv-{business}/data/{application}/{environment}/"
    for prefix in prefixes:
        if "*" in prefix or ".." in prefix or not prefix.startswith(expected_prefix):
            raise IdentityError(f"{path}.allowed_secret_prefixes escapes the workload boundary")
    denials = set(require_nonempty_list(value.get("denied_capabilities"), f"{path}.denied_capabilities"))
    if not REQUIRED_DENIALS.issubset(denials):
        raise IdentityError(f"{path}.denied_capabilities omits required denial classes")

    readback = value.get("identity_readback")
    readback_required = {"subject", "audiences", "business", "application", "environment", "ttl_seconds"}
    if not isinstance(readback, dict) or set(readback) != readback_required:
        raise IdentityError(f"{path}.identity_readback is invalid")
    if readback.get("subject") != subject:
        raise IdentityError(f"{path}.identity_readback.subject does not match")
    if readback.get("audiences") != audiences:
        raise IdentityError(f"{path}.identity_readback.audiences does not match")
    for name, expected in (("business", business), ("application", application), ("environment", environment)):
        if readback.get(name) != expected:
            raise IdentityError(f"{path}.identity_readback.{name} does not match")
    readback_ttl = readback.get("ttl_seconds")
    if isinstance(readback_ttl, bool) or not isinstance(readback_ttl, int) or readback_ttl <= 0 or readback_ttl > ttl:
        raise IdentityError(f"{path}.identity_readback.ttl_seconds is invalid")

    tests = value.get("tests")
    required_tests = set(policy["required_tests"])
    if not isinstance(tests, dict) or set(tests) != required_tests:
        raise IdentityError(f"{path}.tests must contain the exact required test set")
    failed = sorted(name for name, result in tests.items() if result != "PASS")
    if failed:
        raise IdentityError(f"{path}.tests failed or incomplete: {failed}")

    authority_fields = (
        "business_write_authority", "communications_delivery_authority",
        "provider_effect_authority", "financial_or_trading_mutation_authority"
    )
    enabled = sorted(name for name in authority_fields if value.get(name) is not False)
    if enabled:
        raise IdentityError(f"{path} grants forbidden runtime authority: {enabled}")
    require_reference(value.get("evidence_ref"), f"{path}.evidence_ref")
    return dict(value)


def validate_summary(value: Any, expected: int) -> dict[str, int]:
    required = {
        "expected", "observed", "shared_wildcard_identities", "long_lived_credentials",
        "cross_business_leaks", "expired_credential_failures", "revocation_failures",
        "wrong_audience_failures", "forbidden_authority_grants"
    }
    if not isinstance(value, dict) or set(value) != required:
        raise IdentityError("summary fields are incomplete or unexpected")
    if value.get("expected") != expected or value.get("observed") != expected:
        raise IdentityError("summary identity count does not match policy")
    for name in required - {"expected", "observed"}:
        observed = value.get(name)
        if isinstance(observed, bool) or not isinstance(observed, int) or observed != 0:
            raise IdentityError(f"summary.{name} must be zero")
    return dict(value)


def validate_safety(value: Any) -> dict[str, bool]:
    required = {
        "credentials_recorded", "identities_issued_by_validator", "business_writes",
        "communications_delivery", "provider_effects", "financial_or_trading_mutation"
    }
    if not isinstance(value, dict) or set(value) != required:
        raise IdentityError("safety fields are incomplete or unexpected")
    enabled = sorted(name for name, state in value.items() if state is not False)
    if enabled:
        raise IdentityError(f"safety fields must remain false: {enabled}")
    return {name: False for name in sorted(required)}


def validate(evidence: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    reject_sensitive_or_unresolved(evidence)
    required_root = {"schema_version", "release_id", "identities", "summary", "safety"}
    if set(evidence) != required_root or evidence.get("schema_version") != 1:
        raise IdentityError("evidence root fields are incomplete or unexpected")
    release_id = require_id(evidence.get("release_id"), "release_id")
    expected = int(policy["expected_identities"])
    identities_raw = evidence.get("identities")
    if not isinstance(identities_raw, list) or len(identities_raw) != expected:
        raise IdentityError(f"identities must contain exactly {expected} entries")
    identities = [validate_identity(item, index, policy) for index, item in enumerate(identities_raw)]
    workload_ids = [item["workload_id"] for item in identities]
    subjects = [item["subject"] for item in identities]
    if len(workload_ids) != len(set(workload_ids)):
        raise IdentityError("workload identity IDs must be unique")
    if len(subjects) != len(set(subjects)):
        raise IdentityError("workload subjects must be unique")
    return {
        "schema_version": 1,
        "status": "PASS",
        "release_id": release_id,
        "identities": sorted(identities, key=lambda item: item["workload_id"]),
        "summary": validate_summary(evidence.get("summary"), expected),
        "safety": validate_safety(evidence.get("safety")),
        "credential_values_recorded": False,
        "runtime_contacted_by_validator": False,
        "production_changed": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--result-output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = validate(load_json(args.evidence), load_json(args.policy))
    except IdentityError as exc:
        print("WORKLOAD_IDENTITY_CERTIFICATION=BLOCKED", file=sys.stderr)
        print(f"BLOCKER={exc}", file=sys.stderr)
        return 2
    if args.result_output:
        args.result_output.parent.mkdir(parents=True, exist_ok=True)
        args.result_output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("WORKLOAD_IDENTITY_CERTIFICATION=PASS")
    print(f"IDENTITIES={len(result['identities'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
