#!/usr/bin/env python3
"""Validate signed, scanned, SBOM-backed final artifact evidence.

The validator consumes sanitized evidence created by component-owned build workflows.
It does not build, pull, sign, scan, attest, publish, deploy, or contact a runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "config" / "final-artifact-verification-policy.v1.json"
DEFAULT_MATRIX = ROOT / "IMMUTABLE-CANDIDATE-MATRIX.yaml"
DEFAULT_MATRIX_SCHEMA = ROOT / "config" / "immutable-workload-evidence.v1.schema.json"
TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from validate_immutable_candidate_matrix_final import (  # noqa: E402
    canonical_candidates,
    validate as validate_candidate_matrix,
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
FORBIDDEN = (
    "UNKNOWN", "PENDING", "NOT_RUN", "NOT_STARTED", "NONE", "TBD", "TODO",
    "REPLACE_ME", "UNVERIFIED", "UNRESOLVED", "LOCAL_ONLY", "PLACEHOLDER"
)
SECRET_KEYS = (
    "password", "private_key", "secret_value", "access_token", "refresh_token",
    "authorization_value", "cookie_value", "client_secret", "ssh_key", "token_value"
)


class ArtifactError(RuntimeError):
    """Malformed or failing artifact evidence."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"cannot parse JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ArtifactError(f"JSON root must be an object: {path}")
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
                raise ArtifactError(f"unresolved value at {path}")
            if "-----BEGIN" in child or upper.startswith("BEARER "):
                raise ArtifactError(f"credential-shaped value at {path}")
        if isinstance(child, dict):
            for key, item in child.items():
                normalized = str(key).lower().replace("-", "_")
                if any(fragment in normalized for fragment in SECRET_KEYS):
                    if item not in (None, False, "") and not normalized.endswith("_ref"):
                        raise ArtifactError(f"secret value field is prohibited at {path}.{key}")


def require_reference(value: Any, path: str) -> str:
    if not isinstance(value, str) or len(value.strip()) < 8:
        raise ArtifactError(f"{path} must be a non-empty evidence reference")
    if any(marker in value.upper() for marker in FORBIDDEN):
        raise ArtifactError(f"{path} is unresolved")
    parsed = urlsplit(value)
    if parsed.scheme in {"http", "https"} and (parsed.username or parsed.password):
        raise ArtifactError(f"{path} must not embed credentials")
    return value


def parse_time(value: Any, path: str) -> datetime:
    if not isinstance(value, str):
        raise ArtifactError(f"{path} must be an RFC3339 timestamp")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        result = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ArtifactError(f"{path} must be an RFC3339 timestamp") from exc
    if result.tzinfo is None:
        raise ArtifactError(f"{path} must include a timezone")
    return result.astimezone(timezone.utc)


def require_pass(value: Any, path: str) -> None:
    if value != "PASS":
        raise ArtifactError(f"{path} must be PASS")


def validate_signature(
    value: Any, path: str, policy: dict[str, Any], expected_image: str
) -> dict[str, str]:
    required = {"status", "subject_image", "certificate_identity", "certificate_oidc_issuer", "bundle_ref"}
    if not isinstance(value, dict) or set(value) != required:
        raise ArtifactError(f"{path} fields are incomplete or unexpected")
    require_pass(value.get("status"), f"{path}.status")
    identity = require_reference(value.get("certificate_identity"), f"{path}.certificate_identity")
    issuer = value.get("certificate_oidc_issuer")
    if issuer != policy["required_signature_issuer"]:
        raise ArtifactError(f"{path}.certificate_oidc_issuer is not the approved issuer")
    if not identity.startswith(policy["required_certificate_identity_prefix"]):
        raise ArtifactError(f"{path}.certificate_identity is outside the approved GitHub authority")
    if value.get("subject_image") != expected_image:
        raise ArtifactError(f"{path}.subject_image differs from the artifact image")
    require_reference(value.get("bundle_ref"), f"{path}.bundle_ref")
    return dict(value)


def validate_sbom(value: Any, path: str, policy: dict[str, Any]) -> dict[str, str]:
    required = {"status", "format", "reference", "sha256"}
    if not isinstance(value, dict) or set(value) != required:
        raise ArtifactError(f"{path} fields are incomplete or unexpected")
    require_pass(value.get("status"), f"{path}.status")
    if value.get("format") not in set(policy["allowed_sbom_formats"]):
        raise ArtifactError(f"{path}.format is not approved")
    require_reference(value.get("reference"), f"{path}.reference")
    checksum = value.get("sha256")
    if not isinstance(checksum, str) or not HEX64_RE.fullmatch(checksum):
        raise ArtifactError(f"{path}.sha256 is invalid")
    return dict(value)


def validate_provenance(
    value: Any,
    path: str,
    policy: dict[str, Any],
    expected_image: str,
    expected_repository: str,
    expected_source_sha: str,
) -> dict[str, str]:
    required = {
        "status", "subject_image", "source_repository", "source_sha",
        "predicate_type", "reference",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ArtifactError(f"{path} fields are incomplete or unexpected")
    require_pass(value.get("status"), f"{path}.status")
    if value.get("predicate_type") != policy["required_provenance_predicate"]:
        raise ArtifactError(f"{path}.predicate_type is not the required SLSA predicate")
    if value.get("subject_image") != expected_image:
        raise ArtifactError(f"{path}.subject_image differs from the artifact image")
    if value.get("source_repository") != expected_repository:
        raise ArtifactError(f"{path}.source_repository differs from the artifact repository")
    if value.get("source_sha") != expected_source_sha:
        raise ArtifactError(f"{path}.source_sha differs from the artifact source")
    require_reference(value.get("reference"), f"{path}.reference")
    return dict(value)


def validate_vulnerability(value: Any, path: str, policy: dict[str, Any], now: datetime) -> dict[str, Any]:
    required = {"status", "scanner", "database_updated_at", "critical", "high", "reference"}
    if not isinstance(value, dict) or set(value) != required:
        raise ArtifactError(f"{path} fields are incomplete or unexpected")
    require_pass(value.get("status"), f"{path}.status")
    require_reference(value.get("scanner"), f"{path}.scanner")
    updated = parse_time(value.get("database_updated_at"), f"{path}.database_updated_at")
    age_hours = (now - updated).total_seconds() / 3600
    if age_hours < 0:
        raise ArtifactError(f"{path}.database_updated_at is in the future")
    if age_hours > policy["maximum_vulnerability_database_age_hours"]:
        raise ArtifactError(f"{path} vulnerability database is stale")
    for name, policy_name in (
        ("critical", "maximum_critical_vulnerabilities"),
        ("high", "maximum_high_vulnerabilities"),
    ):
        count = value.get(name)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ArtifactError(f"{path}.{name} is invalid")
        if count > policy[policy_name]:
            raise ArtifactError(f"{path}.{name} exceeds policy")
    require_reference(value.get("reference"), f"{path}.reference")
    return dict(value)


def validate_artifact(value: Any, index: int, policy: dict[str, Any], now: datetime) -> dict[str, Any]:
    path = f"artifacts[{index}]"
    required = {
        "workload_id", "repository", "source_sha", "build_run", "image",
        "image_digest", "architectures", "configuration_sha256", "signature",
        "sbom", "provenance", "vulnerability_scan", "secret_scan",
        "dependency_audit", "license_review", "attestation_verification",
        "rollback_digest", "evidence_ref"
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ArtifactError(f"{path} fields are incomplete or unexpected")
    workload = value.get("workload_id")
    repository = value.get("repository")
    source_sha = value.get("source_sha")
    image = value.get("image")
    digest = value.get("image_digest")
    rollback = value.get("rollback_digest")
    config_hash = value.get("configuration_sha256")
    if not isinstance(workload, str) or not ID_RE.fullmatch(workload):
        raise ArtifactError(f"{path}.workload_id is invalid")
    if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository):
        raise ArtifactError(f"{path}.repository is invalid")
    if not isinstance(source_sha, str) or not SHA_RE.fullmatch(source_sha):
        raise ArtifactError(f"{path}.source_sha is invalid")
    require_reference(value.get("build_run"), f"{path}.build_run")
    if not isinstance(image, str) or not IMAGE_RE.fullmatch(image):
        raise ArtifactError(f"{path}.image must be repository@sha256")
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise ArtifactError(f"{path}.image_digest is invalid")
    if image.rsplit("@", 1)[-1] != digest:
        raise ArtifactError(f"{path} image reference and digest disagree")
    architectures = value.get("architectures")
    if not isinstance(architectures, list) or not architectures:
        raise ArtifactError(f"{path}.architectures must be non-empty")
    if len(architectures) != len(set(architectures)) or set(architectures) - set(policy["allowed_architectures"]):
        raise ArtifactError(f"{path}.architectures contains duplicates or unsupported values")
    if not isinstance(config_hash, str) or not HEX64_RE.fullmatch(config_hash):
        raise ArtifactError(f"{path}.configuration_sha256 is invalid")
    if not isinstance(rollback, str) or not DIGEST_RE.fullmatch(rollback):
        raise ArtifactError(f"{path}.rollback_digest is invalid")
    if rollback == digest:
        raise ArtifactError(f"{path}.rollback_digest must differ from the candidate")
    for name in ("secret_scan", "dependency_audit", "license_review", "attestation_verification"):
        require_pass(value.get(name), f"{path}.{name}")
    require_reference(value.get("evidence_ref"), f"{path}.evidence_ref")

    normalized = dict(value)
    normalized["signature"] = validate_signature(value.get("signature"), f"{path}.signature", policy, image)
    normalized["sbom"] = validate_sbom(value.get("sbom"), f"{path}.sbom", policy)
    normalized["provenance"] = validate_provenance(
        value.get("provenance"), f"{path}.provenance", policy, image, repository, source_sha
    )
    normalized["vulnerability_scan"] = validate_vulnerability(
        value.get("vulnerability_scan"), f"{path}.vulnerability_scan", policy, now
    )
    return normalized


def validate_summary(value: Any, expected: int) -> dict[str, int]:
    required = {
        "expected", "observed", "critical_vulnerabilities", "high_vulnerabilities",
        "unsigned_artifacts", "missing_sboms", "missing_provenance", "mutable_images"
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ArtifactError("summary fields are incomplete or unexpected")
    if value.get("expected") != expected or value.get("observed") != expected:
        raise ArtifactError("summary expected/observed count mismatch")
    for name in required - {"expected", "observed"}:
        count = value.get(name)
        if isinstance(count, bool) or not isinstance(count, int) or count != 0:
            raise ArtifactError(f"summary.{name} must be zero")
    return dict(value)


def validate_safety(value: Any) -> dict[str, bool]:
    required = {
        "deployment_performed", "business_writes", "communications_delivery",
        "provider_effects", "financial_or_trading_mutation"
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ArtifactError("safety fields are incomplete or unexpected")
    enabled = sorted(name for name, state in value.items() if state is not False)
    if enabled:
        raise ArtifactError(f"safety fields must remain false: {enabled}")
    return {name: False for name in sorted(required)}


def bind_artifacts_to_matrix(
    artifacts: list[dict[str, Any]],
    matrix: dict[str, Any],
    matrix_schema: dict[str, Any],
    expected: int,
) -> None:
    matrix_result = validate_candidate_matrix(
        matrix, matrix_schema, expected=expected, require_authorized=True
    )
    if matrix_result["status"] != "PASS":
        codes = sorted({item["code"] for item in matrix_result["findings"]})
        raise ArtifactError(f"immutable candidate matrix is blocked: {','.join(codes)}")

    candidates = canonical_candidates(matrix)
    artifact_ids = {item["workload_id"] for item in artifacts}
    if artifact_ids != set(candidates):
        raise ArtifactError("artifact workload IDs differ from the immutable candidate matrix")

    comparisons = {
        "repository": "repository",
        "source_sha": "protected_source_sha",
        "image": "image",
        "image_digest": "image_digest",
        "configuration_sha256": "configuration_sha256",
        "rollback_digest": "rollback_digest",
    }
    for artifact in artifacts:
        workload = artifact["workload_id"]
        candidate = candidates[workload]
        for artifact_field, candidate_field in comparisons.items():
            if artifact[artifact_field] != candidate[candidate_field]:
                raise ArtifactError(
                    f"artifacts[{workload}].{artifact_field} differs from the immutable candidate matrix"
                )
        for family in ("signature", "provenance"):
            if artifact[family]["subject_image"] != candidate[family]["subject_image"]:
                raise ArtifactError(
                    f"artifacts[{workload}].{family}.subject_image differs from the immutable candidate matrix"
                )
        provenance = artifact["provenance"]
        candidate_provenance = candidate["provenance"]
        for field in ("source_repository", "source_sha"):
            if provenance[field] != candidate_provenance[field]:
                raise ArtifactError(
                    f"artifacts[{workload}].provenance.{field} differs from the immutable candidate matrix"
                )


def validate(
    evidence: dict[str, Any],
    policy: dict[str, Any],
    *,
    matrix: dict[str, Any],
    matrix_schema: dict[str, Any],
    authority_sha: str,
    matrix_sha256: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    reject_sensitive_or_unresolved(evidence)
    if not isinstance(authority_sha, str) or not SHA_RE.fullmatch(authority_sha):
        raise ArtifactError("authority_sha must be the exact checked-out 40-character commit")
    if matrix_sha256 is None:
        canonical = json.dumps(matrix, sort_keys=True, separators=(",", ":")).encode()
        matrix_sha256 = hashlib.sha256(canonical).hexdigest()
    if not HEX64_RE.fullmatch(matrix_sha256):
        raise ArtifactError("matrix_sha256 is invalid")
    required_root = {"schema_version", "release_id", "artifacts", "summary", "safety"}
    if set(evidence) != required_root or evidence.get("schema_version") != 1:
        raise ArtifactError("evidence root fields are incomplete or unexpected")
    release_id = evidence.get("release_id")
    if not isinstance(release_id, str) or not ID_RE.fullmatch(release_id):
        raise ArtifactError("release_id is invalid")
    expected = int(policy["expected_artifacts"])
    artifacts_raw = evidence.get("artifacts")
    if not isinstance(artifacts_raw, list) or len(artifacts_raw) != expected:
        raise ArtifactError(f"artifacts must contain exactly {expected} entries")
    current_time = now or datetime.now(timezone.utc)
    artifacts = [
        validate_artifact(item, index, policy, current_time)
        for index, item in enumerate(artifacts_raw)
    ]
    workload_ids = [item["workload_id"] for item in artifacts]
    images = [item["image"] for item in artifacts]
    digests = [item["image_digest"] for item in artifacts]
    if len(workload_ids) != len(set(workload_ids)):
        raise ArtifactError("workload IDs must be unique")
    if len(images) != len(set(images)) or len(digests) != len(set(digests)):
        raise ArtifactError("final image references and digests must be unique per workload")
    bind_artifacts_to_matrix(artifacts, matrix, matrix_schema, expected)
    return {
        "schema_version": 1,
        "status": "PASS",
        "release_id": release_id,
        "authority_source_sha": authority_sha,
        "immutable_matrix_sha256": matrix_sha256,
        "artifacts": sorted(artifacts, key=lambda item: item["workload_id"]),
        "summary": validate_summary(evidence.get("summary"), expected),
        "safety": validate_safety(evidence.get("safety")),
        "secret_values_recorded": False,
        "artifacts_built_by_validator": 0,
        "artifacts_published_by_validator": 0,
        "production_changed": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--matrix-schema", type=Path, default=DEFAULT_MATRIX_SCHEMA)
    parser.add_argument("--authority-sha")
    parser.add_argument("--result-output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        import yaml
    except ImportError as exc:
        print("FINAL_ARTIFACT_EVIDENCE=BLOCKED", file=sys.stderr)
        print(f"BLOCKER={exc}", file=sys.stderr)
        return 2
    try:
        checked_out_head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        authority_sha = args.authority_sha or checked_out_head
        if checked_out_head != authority_sha:
            raise ArtifactError("authority_sha differs from the checked-out exact head")
        matrix_bytes = args.matrix.read_bytes()
        matrix = yaml.safe_load(matrix_bytes)
        matrix_schema = load_json(args.matrix_schema)
        result = validate(
            load_json(args.evidence),
            load_json(args.policy),
            matrix=matrix,
            matrix_schema=matrix_schema,
            authority_sha=authority_sha,
            matrix_sha256=hashlib.sha256(matrix_bytes).hexdigest(),
        )
    except (ArtifactError, OSError, yaml.YAMLError, subprocess.SubprocessError) as exc:
        print("FINAL_ARTIFACT_EVIDENCE=BLOCKED", file=sys.stderr)
        print(f"BLOCKER={exc}", file=sys.stderr)
        return 2
    if args.result_output:
        args.result_output.parent.mkdir(parents=True, exist_ok=True)
        args.result_output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("FINAL_ARTIFACT_EVIDENCE=PASS")
    print(f"ARTIFACTS={len(result['artifacts'])}")
    print("CRITICAL_VULNERABILITIES=0")
    print("HIGH_VULNERABILITIES=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
