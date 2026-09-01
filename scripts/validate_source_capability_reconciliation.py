#!/usr/bin/env python3
"""Validate the protected-source overlay without treating it as runtime proof."""

from pathlib import Path
import re
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "PROTECTED-SOURCE-CAPABILITY-RECONCILIATION.yaml"
RUNTIME = ROOT / "IMMUTABLE-CANDIDATE-MATRIX.yaml"
RUNTIME_AUTHORITY_MERGE = "bd99e533e46b36f018a990f0c742643534e08f88"
CAPABILITIES = {
    "advertising_write", "external_delivery", "social_publish",
    "external_model_call", "sms_delivery", "email_delivery",
    "pstn_dialing", "n8n_provider_write",
}
EXPECTED = {
    "codestra-beyvra-email-api-1": (
        "Codestra-SRL/codestra-middleware",
        "eff30875864d6c9fa2ca789e9fc5fd906d51b729",
    ),
    "codestra-email-reseller-api-1": (
        "appolon1908-hue/codestra-production-platform",
        "46463acbbf3e4df95926ac2e0ea8baae9a4abfa5",
    ),
    "codestra-mail-api-mail-api-1": (
        "appolon1908-hue/codestra-production-platform",
        "a0593cb881654999f78e2c40d6f9784a5507d987",
    ),
    "codestra-provisioning-service-provisioning-service-1": (
        "appolon1908-hue/codestra-provisioning-service",
        "2c18e395e9f86f7510f142188336e9114aa213a4",
    ),
    "codestra-reseller-portal-portal-1": (
        "appolon1908-hue/codestra-production-platform",
        "9d2805ca397b7fdafab0e913cd442126fe1391d2",
    ),
}
EMAIL_CAPABILITIES = {
    "advertising_write": False,
    "external_delivery": True,
    "social_publish": False,
    "external_model_call": False,
    "sms_delivery": False,
    "email_delivery": True,
    "pstn_dialing": False,
    "n8n_provider_write": False,
}
NO_EFFECT_CAPABILITIES = {name: False for name in CAPABILITIES}
EXPECTED_CAPABILITIES = {
    "codestra-beyvra-email-api-1": EMAIL_CAPABILITIES,
    "codestra-email-reseller-api-1": EMAIL_CAPABILITIES,
    "codestra-mail-api-mail-api-1": EMAIL_CAPABILITIES,
    "codestra-provisioning-service-provisioning-service-1": EMAIL_CAPABILITIES,
    "codestra-reseller-portal-portal-1": NO_EFFECT_CAPABILITIES,
}


def fail(message: str) -> None:
    raise ValueError(message)


def validate(overlay: dict, runtime: dict) -> None:
    if overlay.get("schema") != "codestra.protected-source-capability-reconciliation.v1":
        fail("unexpected overlay schema")
    if overlay.get("production_changed") is not False:
        fail("overlay must assert production_changed=false")
    if overlay.get("runtime_verified") is not False:
        fail("source evidence must never assert runtime verification")
    if overlay.get("based_on_runtime_authority_merge") != RUNTIME_AUTHORITY_MERGE:
        fail("runtime authority merge differs from the reviewed immutable capture")

    workloads = overlay.get("workloads", {})
    if set(workloads) != set(EXPECTED):
        fail("overlay workload coverage differs from the required historical UNKNOWN set")
    runtime_candidates = runtime.get("candidates", {})
    missing = set(EXPECTED) - set(runtime_candidates)
    if missing:
        fail(f"overlay workload absent from immutable runtime capture: {sorted(missing)}")

    for name, record in workloads.items():
        expected_repository, expected_sha = EXPECTED[name]
        if record.get("repository") != runtime_candidates[name].get("repository"):
            fail(f"{name}: repository differs from immutable runtime capture")
        if record.get("repository") != expected_repository:
            fail(f"{name}: repository differs from reviewed source authority")
        if record.get("source_status") != "PROTECTED_MERGE":
            fail(f"{name}: source_status must be PROTECTED_MERGE")
        if not re.fullmatch(r"[0-9a-f]{40}", record.get("protected_source_sha", "")):
            fail(f"{name}: protected_source_sha must be an exact SHA")
        if record.get("protected_source_sha") != expected_sha:
            fail(f"{name}: protected_source_sha differs from reviewed merge")
        capabilities = record.get("capabilities", {})
        if set(capabilities) != CAPABILITIES:
            fail(f"{name}: capability keys are incomplete or unexpected")
        if any(type(value) is not bool for value in capabilities.values()):
            fail(f"{name}: every source capability must be boolean")
        if capabilities != EXPECTED_CAPABILITIES[name]:
            fail(f"{name}: capabilities differ from the reviewed source classification")


def main() -> int:
    try:
        validate(yaml.safe_load(OVERLAY.read_text()), yaml.safe_load(RUNTIME.read_text()))
    except (OSError, yaml.YAMLError, ValueError) as error:
        print(f"source capability reconciliation: FAIL: {error}", file=sys.stderr)
        return 1
    print("source capability reconciliation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
