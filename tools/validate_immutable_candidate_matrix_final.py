#!/usr/bin/env python3
"""Validate the final 64-workload immutable candidate matrix fail closed."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

import yaml

ROOT = Path(__file__).resolve().parents[1]
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
IMAGE_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
FORBIDDEN = {
    "UNKNOWN", "PENDING", "NOT_STARTED", "NOT_RUN", "NONE", "TBD",
    "TODO", "REPLACE_ME", "UNRESOLVED", "UNVERIFIED", "LOCAL_ONLY"
}
ID_KEYS = {"workload", "workload_id", "id", "name", "service", "component"}
REPO_KEYS = {"repository", "repo", "source_repository", "source_repo"}
SHA_KEYS = {"source_sha", "protected_source_sha", "git_sha", "commit_sha", "revision"}
IMAGE_KEYS = {"image", "image_ref", "image_reference", "oci_image"}
DIGEST_KEYS = {"image_digest", "digest", "oci_digest"}
ROLLBACK_KEYS = {"rollback_digest", "previous_digest", "rollback_image_digest"}
SIGNATURE_KEYS = {"signature", "signature_ref", "signature_reference", "cosign_bundle"}
SBOM_KEYS = {"sbom", "sbom_ref", "sbom_reference"}
PROVENANCE_KEYS = {"provenance", "provenance_ref", "provenance_reference", "attestation"}


def key(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def walk(value: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for name, child in value.items():
            yield from walk(child, f"{path}.{name}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{path}[{index}]")


def first(mapping: dict[str, Any], names: set[str]) -> Any:
    for name, value in mapping.items():
        if key(name) in names:
            return value
    return None


def unresolved(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    text = str(value).strip().upper()
    return not text or any(item == text or item in text for item in FORBIDDEN)


def collect_entries(document: Any) -> dict[str, tuple[str, dict[str, Any]]]:
    entries: dict[str, tuple[str, dict[str, Any]]] = {}
    for path, value in walk(document):
        if not isinstance(value, dict):
            continue
        workload = first(value, ID_KEYS)
        evidence = [
            first(value, REPO_KEYS), first(value, SHA_KEYS),
            first(value, IMAGE_KEYS), first(value, DIGEST_KEYS)
        ]
        if workload is None or sum(item is not None for item in evidence) < 3:
            continue
        workload_id = str(workload).strip()
        if workload_id and workload_id not in entries:
            entries[workload_id] = (path, value)
    return entries


def deployment_authorized(document: Any) -> bool | None:
    observed: list[bool] = []
    for _, value in walk(document):
        if isinstance(value, dict):
            for name, child in value.items():
                if key(name) in {"deployment_authorized", "deploy_authorized"} and isinstance(child, bool):
                    observed.append(child)
    if True in observed:
        return True
    if False in observed:
        return False
    return None


def validate(document: Any, expected: int = 64, require_authorized: bool = True) -> dict[str, Any]:
    findings: list[dict[str, str]] = []

    def add(code: str, path: str, detail: str) -> None:
        findings.append({"code": code, "path": path, "detail": detail})

    for path, value in walk(document):
        if isinstance(value, str):
            if unresolved(value):
                add("UNRESOLVED_VALUE", path, "placeholder or unresolved value")
            if ":latest" in value:
                add("MUTABLE_IMAGE", path, "latest tag is prohibited")

    entries = collect_entries(document)
    if len(entries) != expected:
        add("WORKLOAD_COUNT", "$", f"expected {expected} unique workloads, found {len(entries)}")

    for workload_id, (path, value) in sorted(entries.items()):
        repository = first(value, REPO_KEYS)
        source_sha = first(value, SHA_KEYS)
        image = first(value, IMAGE_KEYS)
        digest = first(value, DIGEST_KEYS)
        if digest is None and isinstance(image, str) and "@" in image:
            digest = image.rsplit("@", 1)[-1]
        signature = first(value, SIGNATURE_KEYS)
        sbom = first(value, SBOM_KEYS)
        provenance = first(value, PROVENANCE_KEYS)
        rollback = first(value, ROLLBACK_KEYS)

        if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository.strip()):
            add("REPOSITORY", path, f"{workload_id}: repository must be owner/name")
        if not isinstance(source_sha, str) or not SHA_RE.fullmatch(source_sha.strip().lower()):
            add("SOURCE_SHA", path, f"{workload_id}: exact protected source SHA required")
        if not isinstance(image, str) or not IMAGE_RE.fullmatch(image.strip().lower()):
            add("IMAGE", path, f"{workload_id}: immutable repository@sha256 image required")
        if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest.strip().lower()):
            add("DIGEST", path, f"{workload_id}: exact image digest required")
        elif isinstance(image, str) and image.rsplit("@", 1)[-1].lower() != digest.strip().lower():
            add("IMAGE_DIGEST_MISMATCH", path, f"{workload_id}: image and digest disagree")
        for code, label, evidence in (
            ("SIGNATURE", "signature", signature),
            ("SBOM", "SBOM", sbom),
            ("PROVENANCE", "provenance", provenance),
        ):
            if unresolved(evidence):
                add(code, path, f"{workload_id}: {label} evidence required")
        if not isinstance(rollback, str) or not DIGEST_RE.fullmatch(rollback.strip().lower()):
            add("ROLLBACK", path, f"{workload_id}: exact rollback digest required")
        elif isinstance(digest, str) and rollback.strip().lower() == digest.strip().lower():
            add("ROLLBACK_NOOP", path, f"{workload_id}: rollback must differ from candidate")

    authorized = deployment_authorized(document)
    if require_authorized and authorized is not True:
        add("DEPLOYMENT_AUTHORIZATION", "$", "deployment_authorized must be true")

    return {
        "schema_version": 1,
        "status": "PASS" if not findings else "BLOCKED",
        "expected_workloads": expected,
        "observed_workloads": len(entries),
        "deployment_authorized": authorized,
        "finding_count": len(findings),
        "findings": findings,
        "runtime_contacted": False,
        "deployment_performed": False,
        "production_changed": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", type=Path, default=ROOT / "IMMUTABLE-CANDIDATE-MATRIX.yaml")
    parser.add_argument("--expected-workloads", type=int, default=64)
    parser.add_argument("--allow-unauthorized", action="store_true")
    parser.add_argument("--evidence-output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        document = yaml.safe_load(args.matrix.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        print(f"IMMUTABLE_MATRIX_ERROR={exc}", file=sys.stderr)
        return 1
    result = validate(
        document,
        expected=args.expected_workloads,
        require_authorized=not args.allow_unauthorized,
    )
    if args.evidence_output:
        args.evidence_output.parent.mkdir(parents=True, exist_ok=True)
        args.evidence_output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"IMMUTABLE_CANDIDATE_MATRIX={result['status']}")
    print(f"WORKLOADS={result['observed_workloads']}/{result['expected_workloads']}")
    print(f"FINDINGS={result['finding_count']}")
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
