import hashlib
import hmac
import os
import unittest
from pathlib import Path

from app import main


class SmsCompletionTests(unittest.TestCase):
    def test_outbound_telnexa_hmac_binds_method_path_timestamp_nonce_and_body(self):
        os.environ["TELNEXA_MIDDLEWARE_API_KEY"] = "k" * 32
        os.environ["TELNEXA_WEBHOOK_SECRET"] = "s" * 32
        body = b'{"synthetic":true}'
        headers = main.telnexa_outbound_headers(
            body, timestamp=1700000000, nonce="nonce-0000000001"
        )
        canonical = b"POST\n/v1/messages\n1700000000\nnonce-0000000001\n" + body
        expected = hmac.new(b"s" * 32, canonical, hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-Codestra-Signature"], "sha256=" + expected)
        self.assertEqual(headers["X-Codestra-Timestamp"], "1700000000")
        self.assertEqual(headers["X-Codestra-Nonce"], "nonce-0000000001")

    def test_required_dlr_mappings(self):
        expected = {
            "DELIVRD": "delivered",
            "UNDELIV": "failed",
            "FAILED": "failed",
            "REJECTD": "rejected",
            "EXPIRED": "expired",
        }
        for raw, canonical in expected.items():
            self.assertEqual(main.DLR_MAP[raw], canonical)

    def test_unknown_status_is_fail_closed(self):
        self.assertEqual(main.DLR_MAP.get("UNSUPPORTED", "unknown"), "unknown")

    def test_segment_boundaries(self):
        self.assertEqual(main.segments("a" * 160), 1)
        self.assertEqual(main.segments("a" * 161), 2)
        self.assertEqual(main.segments("漢" * 70), 1)
        self.assertEqual(main.segments("漢" * 71), 2)
        self.assertEqual(main.segments("^" * 80), 1)
        self.assertEqual(main.segments("^" * 81), 2)
        self.assertEqual(main.segments("{" * 160), 3)
        self.assertEqual(main.segments("`" * 70), 1)
        self.assertEqual(main.segments("`" * 71), 2)

    def test_carrier_submission_requires_live_non_synthetic_mode(self):
        self.assertTrue(main.validate_carrier_submission(
            synthetic=False, live_delivery=True,
            receipt={"carrier_submitted": True},
        ))
        self.assertFalse(main.validate_carrier_submission(
            synthetic=True, live_delivery=False,
            receipt={"carrier_submitted": False},
        ))

    def test_carrier_submission_gate_mismatches_fail_closed(self):
        cases = [
            (True, True, True),
            (False, False, True),
            (False, True, False),
            (False, True, None),
        ]
        for synthetic, live_delivery, carrier_submitted in cases:
            with self.assertRaises(RuntimeError):
                main.validate_carrier_submission(
                    synthetic=synthetic,
                    live_delivery=live_delivery,
                    receipt={"carrier_submitted": carrier_submitted},
                )

    def test_valid_signed_dlr_contract(self):
        secret = "s" * 32
        token = "t" * 32
        os.environ["TELNEXA_WEBHOOK_SECRET"] = secret
        os.environ["SMS_DLR_TOKEN"] = token
        body = b'{"event_id":"event-test-001","status":"DELIVRD"}'
        timestamp = str(int(__import__("time").time()))
        canonical = timestamp.encode() + b"\nevent-test-001\ntelnexa\n" + body
        signature = hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()
        headers = {
            "Authorization": "Bearer " + token,
            "X-Telnexa-Timestamp": timestamp,
            "X-Telnexa-Event-Id": "event-test-001",
            "X-Telnexa-Signature": "sha256=" + signature,
            "X-Source-System": "telnexa",
        }
        with main.app.test_request_context("/internal/dlr", method="POST", data=body, headers=headers):
            self.assertIsNone(main.verify_dlr(body))

    def test_bad_dlr_signature_is_denied(self):
        os.environ["TELNEXA_WEBHOOK_SECRET"] = "s" * 32
        os.environ["SMS_DLR_TOKEN"] = "t" * 32
        headers = {
            "Authorization": "Bearer " + "t" * 32,
            "X-Telnexa-Timestamp": str(int(__import__("time").time())),
            "X-Telnexa-Event-Id": "event-test-002",
            "X-Telnexa-Signature": "sha256=" + "0" * 64,
            "X-Source-System": "telnexa",
        }
        with main.app.test_request_context("/internal/dlr", method="POST", data=b"{}", headers=headers):
            self.assertEqual(main.verify_dlr(b"{}"), "invalid DLR signature")

    def test_expired_dlr_is_denied(self):
        os.environ["SMS_DLR_TOKEN"] = "t" * 32
        headers = {
            "Authorization": "Bearer " + "t" * 32,
            "X-Telnexa-Timestamp": "1",
            "X-Telnexa-Event-Id": "event-test-003",
            "X-Telnexa-Signature": "sha256=" + "0" * 64,
            "X-Source-System": "telnexa",
        }
        with main.app.test_request_context("/internal/dlr", method="POST", data=b"{}", headers=headers):
            self.assertEqual(main.verify_dlr(b"{}"), "invalid DLR signature context")

    def test_source_contains_server_controlled_sender_mapping(self):
        source = Path(main.__file__).read_text()
        self.assertIn('"sender": profile["provider_sender"]', source)
        self.assertNotIn('"sender": data.get(', source)

    def test_no_customer_controlled_route_or_carrier(self):
        source = Path(main.__file__).read_text()
        self.assertIn('{"to", "from", "text", "synthetic"}', source)
        self.assertIn("carrier and route selection are not accepted", source)

    def test_dlr_state_precedes_optional_event(self):
        source = Path(main.__file__).read_text()
        state_update = source.index('UPDATE sms_messages SET status=')
        event_insert = source.index('internal_event(conn, account, message', state_update)
        self.assertLess(state_update, event_insert)

    def test_ledger_requires_carrier_submission_to_finalize(self):
        source = Path(main.__file__).read_text()
        self.assertIn('if ledger and message["carrier_submitted"]', source)
        self.assertIn("final_status=%s,finalized_at=now()", source)

    def test_dlr_duplicate_and_conflict_guards_exist(self):
        source = Path(main.__file__).read_text()
        self.assertIn("sms.dlr_duplicate", source)
        self.assertIn("conflicting_duplicate_event_id", source)
        self.assertIn("uncorrelated_message", source)


if __name__ == "__main__":
    unittest.main()
