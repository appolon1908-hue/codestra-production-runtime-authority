#!/usr/bin/env python3
"""Validate the final 64-workload immutable candidate matrix fail closed."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = ROOT / "config" / "immutable-workload-evidence.v1.schema.json"
FORBIDDEN = {
    "UNKNOWN", "PENDING", "NOT_STARTED", "NOT_RUN", "NONE", "TBD",
    "TODO", "REPLACE_ME", "UNRESOLVED", "UNVERIFIED", "LOCAL_ONLY",
}
AUTHORIZATION_KEYS = {"deployment_authorized", "deploy_authorized"}


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


def unresolved(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    text = str(value).strip().upper()
    return not text or any(item == text or item in text for item in FORBIDDEN)


def canonical_candidates(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        return {}
    candidates = document.get("candidates")
    return candidates if isinstance(candidates, dict) else {}


def deployment_authorization(document: Any) -> tuple[bool | None, list[tuple[str, str]]]:
    """Return only the canonical root decision and reject every nested alias."""
    findings: list[tuple[str, str]] = []
    if not isinstance(document, dict):
        return None, [("$", "matrix root must be an object")]

    root_aliases = [name for name in document if key(name) in AUTHORIZATION_KEYS]
    if root_aliases != ["deployment_authorized"]:
        findings.append(("$", "exactly one canonical root deployment_authorized field is required"))
    authorized = document.get("deployment_authorized")
    if not isinstance(authorized, bool):
        findings.append(("$.deployment_authorized", "root deployment_authorized must be boolean"))
        authorized = None

    for path, value in walk(document):
        if path == "$" or not isinstance(value, dict):
            continue
        for name in value:
            if key(name) in AUTHORIZATION_KEYS:
                findings.append((f"{path}.{name}", "nested deployment authorization is prohibited"))
    return authorized, findings


def schema_errors(value: Any, schema: dict[str, Any], path: tuple[Any, ...] = ()) -> Iterable[tuple[tuple[Any, ...], str]]:
    """Evaluate the closed JSON Schema subset used by immutable workload v1."""
    if "const" in schema and value != schema["const"]:
        yield path, f"{value!r} is not the required constant {schema['const']!r}"
        return
    expected_type = schema.get("type")
    type_matches = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
    }
    if expected_type and not type_matches.get(expected_type, False):
        yield path, f"value must have type {expected_type}"
        return
    if isinstance(value, dict):
        required = set(schema.get("required", []))
        for name in sorted(required - set(value)):
            yield path, f"{name!r} is a required property"
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for name in sorted(set(value) - set(properties)):
                yield path + (name,), "additional property is prohibited"
        for name in sorted(set(value) & set(properties)):
            yield from schema_errors(value[name], properties[name], path + (name,))
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            yield path, f"string is shorter than {schema['minLength']} characters"
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            yield path, f"string does not match {schema['pattern']}"


def format_schema_path(error_path: tuple[Any, ...], workload_id: str) -> str:
    suffix = "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in error_path)
    return f"$.candidates.{workload_id}{suffix}"


def validate(
    document: Any,
    schema: dict[str, Any],
    expected: int = 64,
    require_authorized: bool = True,
) -> dict[str, Any]:
    findings: list[dict[str, str]] = []

    def add(code: str, path: str, detail: str) -> None:
        findings.append({"code": code, "path": path, "detail": detail})

    if not isinstance(document, dict):
        add("MATRIX_ROOT", "$", "matrix root must be an object")
        document = {}
    else:
        if document.get("schema") != "codestra.immutable-candidate-matrix.v1":
            add("MATRIX_SCHEMA", "$.schema", "canonical matrix schema identifier is required")
        if document.get("production_changed") is not False:
            add("PRODUCTION_CHANGED", "$.production_changed", "pre-deployment matrix must remain false")

    for path, value in walk(document):
        if isinstance(value, str):
            if unresolved(value):
                add("UNRESOLVED_VALUE", path, "placeholder or unresolved value")
            if ":latest" in value:
                add("MUTABLE_IMAGE", path, "latest tag is prohibited")

    entries = canonical_candidates(document)
    if len(entries) != expected:
        add("WORKLOAD_COUNT", "$.candidates", f"expected {expected} unique workloads, found {len(entries)}")

    for workload_id, value in sorted(entries.items()):
        path = f"$.candidates.{workload_id}"
        if not isinstance(workload_id, str) or not isinstance(value, dict):
            add("WORKLOAD_RECORD", path, "workload key and evidence record must be valid")
            continue
        for error_path, message in schema_errors(value, schema):
            add("WORKLOAD_SCHEMA", format_schema_path(error_path, workload_id), message)
        if value.get("workload_id") != workload_id:
            add("WORKLOAD_ID_BINDING", path, "record workload_id must equal its candidate key")

        image = value.get("image")
        digest = value.get("image_digest")
        source_sha = value.get("protected_source_sha")
        rollback = value.get("rollback_digest")
        runtime = value.get("runtime_identity")
        if isinstance(image, str) and isinstance(digest, str) and "@" in image:
            if image.rsplit("@", 1)[-1] != digest:
                add("IMAGE_DIGEST_MISMATCH", path, f"{workload_id}: image and digest disagree")
        if isinstance(rollback, str) and isinstance(digest, str) and rollback == digest:
            add("ROLLBACK_NOOP", path, f"{workload_id}: rollback must differ from candidate")
        if isinstance(runtime, dict):
            if runtime.get("source_sha_readback") != source_sha:
                add("RUNTIME_SOURCE_MISMATCH", path, f"{workload_id}: runtime source readback differs")
            if runtime.get("image_digest_readback") != digest:
                add("RUNTIME_DIGEST_MISMATCH", path, f"{workload_id}: runtime digest readback differs")

        signature = value.get("signature")
        if isinstance(signature, dict) and signature.get("subject_image") != image:
            add("SIGNATURE_SUBJECT_MISMATCH", path, f"{workload_id}: signature subject differs")
        provenance = value.get("provenance")
        if isinstance(provenance, dict):
            if provenance.get("subject_image") != image:
                add("PROVENANCE_IMAGE_MISMATCH", path, f"{workload_id}: provenance subject differs")
            if provenance.get("source_repository") != value.get("repository"):
                add("PROVENANCE_REPOSITORY_MISMATCH", path, f"{workload_id}: provenance repository differs")
            if provenance.get("source_sha") != source_sha:
                add("PROVENANCE_SOURCE_MISMATCH", path, f"{workload_id}: provenance source differs")

    authorized, authorization_findings = deployment_authorization(document)
    for path, detail in authorization_findings:
        add("DEPLOYMENT_AUTHORIZATION_STRUCTURE", path, detail)
    if require_authorized and authorized is not True:
        add("DEPLOYMENT_AUTHORIZATION", "$.deployment_authorized", "deployment_authorized must be true")

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
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--expected-workloads", type=int, default=64)
    parser.add_argument("--allow-unauthorized", action="store_true")
    parser.add_argument("--evidence-output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        import yaml
    except ImportError as exc:
        print(f"IMMUTABLE_MATRIX_ERROR={exc}", file=sys.stderr)
        return 1
    try:
        document = yaml.safe_load(args.matrix.read_text(encoding="utf-8"))
        schema = json.loads(args.schema.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"IMMUTABLE_MATRIX_ERROR={exc}", file=sys.stderr)
        return 1
    result = validate(document, schema, expected=args.expected_workloads, require_authorized=not args.allow_unauthorized)
    if args.evidence_output:
        args.evidence_output.parent.mkdir(parents=True, exist_ok=True)
        args.evidence_output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"IMMUTABLE_CANDIDATE_MATRIX={result['status']}")
    print(f"WORKLOADS={result['observed_workloads']}/{result['expected_workloads']}")
    print(f"FINDINGS={result['finding_count']}")
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
