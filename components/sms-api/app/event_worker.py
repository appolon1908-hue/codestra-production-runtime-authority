import hashlib
import hmac
import json
import os
import signal
import time
import urllib.error
import urllib.request

import psycopg
from psycopg.rows import dict_row

MAX_ATTEMPTS = int(os.getenv("SMS_EVENT_MAX_ATTEMPTS", "5"))
POLL_SECONDS = float(os.getenv("SMS_EVENT_POLL_SECONDS", "1"))
running = True


def stop(_signum, _frame):
    global running
    running = False


def envelope(row):
    payload = row["payload"]
    return {
        "event_type": "telnexa." + row["event_type"],
        "event_version": row["event_version"],
        "occurred_at": row["created_at"].isoformat().replace("+00:00", "Z"),
        "tenant_id": row["customer_code"],
        "customer_id": row["customer_code"],
        "correlation_id": row["correlation_id"],
        "idempotency_key": str(row["event_id"]),
        "payload": payload,
        "metadata": {"source": "sms", "sms_postgres_authority": True, "retry_attempt": row["attempt_count"] + 1},
    }


def deliver(row):
    body = json.dumps(envelope(row), sort_keys=True, separators=(",", ":")).encode()
    stamp = str(int(time.time()))
    event_id = str(row["event_id"])
    canonical = b"\n".join((stamp.encode(), event_id.encode(), b"telnexa", body))
    signature = hmac.new(os.environ["TELNEXA_WEBHOOK_SECRET"].encode(), canonical, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        os.environ["SMS_EVENT_CONTROL_PLANE_URL"], body,
        {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + os.environ["TELNEXA_MIDDLEWARE_API_KEY"],
            "X-Event-Id": event_id,
            "X-Timestamp": stamp,
            "X-Signature": "sha256=" + signature,
            "X-Correlation-Id": row["correlation_id"],
        }, method="POST",
    )
    with urllib.request.urlopen(request, timeout=float(os.getenv("SMS_EVENT_TIMEOUT_SECONDS", "5"))) as response:
        if response.status not in (200, 202):
            raise RuntimeError("control_plane_status_%s" % response.status)


def once(conn):
    with conn.transaction():
        row = conn.execute(
            """SELECT event.*, account.customer_code
               FROM sms_internal_events event
               JOIN sms_accounts account ON account.id=event.account_id
               WHERE event.delivery_state IN ('pending','failed') AND event.next_retry_at<=now()
               ORDER BY event.created_at FOR UPDATE OF event SKIP LOCKED LIMIT 1"""
        ).fetchone()
        if not row:
            return False
        conn.execute(
            "UPDATE sms_internal_events SET delivery_state='processing',processing_started_at=now() WHERE id=%s",
            (row["id"],),
        )
    try:
        deliver(row)
    except Exception as exc:
        attempts = row["attempt_count"] + 1
        state = "dead_letter" if attempts >= MAX_ATTEMPTS else "failed"
        delay = min(300, 2 ** attempts)
        conn.execute(
            """UPDATE sms_internal_events SET delivery_state=%s,attempt_count=%s,last_error=%s,
               next_retry_at=now()+(%s * interval '1 second'),processing_started_at=NULL WHERE id=%s""",
            (state, attempts, type(exc).__name__, delay, row["id"]),
        )
    else:
        conn.execute(
            """UPDATE sms_internal_events SET delivery_state='delivered',delivered_at=now(),
               published_at=now(),last_error=NULL,processing_started_at=NULL WHERE id=%s""",
            (row["id"],),
        )
    return True


def main():
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with psycopg.connect(os.environ["DATABASE_URL"], row_factory=dict_row, autocommit=True) as conn:
        conn.execute("UPDATE sms_internal_events SET delivery_state='failed',next_retry_at=now(),processing_started_at=NULL WHERE delivery_state='processing'")
        while running:
            if not once(conn):
                time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
