#!/usr/bin/env python3

import copy
import importlib.util
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "source_capability_validator",
    ROOT / "scripts" / "validate_source_capability_reconciliation.py",
)
VALIDATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VALIDATOR)


class SourceCapabilityReconciliationTest(unittest.TestCase):
    def setUp(self):
        self.overlay = yaml.safe_load(VALIDATOR.OVERLAY.read_text())
        self.runtime = yaml.safe_load(VALIDATOR.RUNTIME.read_text())

    def assert_rejected(self, mutation):
        candidate = copy.deepcopy(self.overlay)
        mutation(candidate)
        with self.assertRaises(ValueError):
            VALIDATOR.validate(candidate, self.runtime)

    def test_current_overlay_is_valid(self):
        VALIDATOR.validate(self.overlay, self.runtime)

    def test_runtime_verification_cannot_be_claimed(self):
        self.assert_rejected(lambda data: data.__setitem__("runtime_verified", True))

    def test_runtime_authority_merge_is_pinned(self):
        self.assert_rejected(
            lambda data: data.__setitem__(
                "based_on_runtime_authority_merge", "0" * 40
            )
        )

    def test_production_change_cannot_be_claimed(self):
        self.assert_rejected(lambda data: data.__setitem__("production_changed", True))

    def test_exact_workload_coverage_is_required(self):
        self.assert_rejected(
            lambda data: data["workloads"].pop("codestra-beyvra-email-api-1")
        )

    def test_exact_protected_sha_is_required(self):
        self.assert_rejected(
            lambda data: data["workloads"]["codestra-beyvra-email-api-1"].__setitem__(
                "protected_source_sha", "UNKNOWN"
            )
        )

    def test_different_well_formed_sha_is_rejected(self):
        self.assert_rejected(
            lambda data: data["workloads"]["codestra-beyvra-email-api-1"].__setitem__(
                "protected_source_sha", "0" * 40
            )
        )

    def test_unknown_capability_is_rejected(self):
        self.assert_rejected(
            lambda data: data["workloads"]["codestra-beyvra-email-api-1"][
                "capabilities"
            ].__setitem__("email_delivery", "UNKNOWN")
        )

    def test_different_boolean_capability_is_rejected(self):
        self.assert_rejected(
            lambda data: data["workloads"]["codestra-beyvra-email-api-1"][
                "capabilities"
            ].__setitem__("email_delivery", False)
        )

    def test_required_ci_invokes_validator_and_mutation_suite(self):
        workflow = (ROOT / ".github" / "workflows" / "authority.yml").read_text()
        assert "python3 -m compileall -q scripts tests" in workflow
        assert "python3 scripts/validate_source_capability_reconciliation.py" in workflow
        assert (
            'python3 -m unittest discover -s tests -p "test_*.py" -v'
            in workflow
        )


if __name__ == "__main__":
    unittest.main()
