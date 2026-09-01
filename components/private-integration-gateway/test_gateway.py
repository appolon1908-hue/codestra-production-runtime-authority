import sqlite3
import tempfile
import unittest

import gateway


class GatewayAuthorityTests(unittest.TestCase):
    def test_kyqra_deduplication_only_applies_to_results(self):
        with tempfile.TemporaryDirectory() as directory:
            gateway.DB = directory + "/gateway.db"
            gateway.initialize()
            with sqlite3.connect(gateway.DB) as conn:
                sql = conn.execute(
                    "SELECT sql FROM sqlite_master WHERE name='kyqra_record_unique'"
                ).fetchone()[0]
            self.assertIn("path='/api/v1/kyqra/results'", sql)

    def test_mock_receipt_has_stable_adapter_identity(self):
        payload = {"idempotency_key": "certification-message-001"}
        first = gateway.mock_adapter_receipt(payload, False)
        replay = gateway.mock_adapter_receipt(payload, True)
        self.assertEqual(first["adapter_message_id"], replay["adapter_message_id"])
        self.assertFalse(first["carrier_submitted"])
        self.assertTrue(replay["duplicate"])

    def test_worker_selects_oldest_ready_events_first(self):
        self.assertIn("ORDER BY created_at ASC", gateway.READY_EVENTS_SQL)


if __name__ == "__main__":
    unittest.main()
