import hashlib
import hmac
import json
import os
import re
import time
import uuid
from decimal import Decimal

import psycopg
import requests
from flask import Flask, Response, g, jsonify, request
from psycopg.rows import dict_row


def verifier(name: str) -> str:
    file_name = os.getenv(f"{name}_SHA256_FILE", "")
    if not file_name:
        raise RuntimeError(f"missing verifier for {name}")
    with open(file_name, "r", encoding="utf-8") as handle:
        value = handle.read().strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise RuntimeError(f"invalid verifier for {name}")
    return value

app = Flask(__name__)
MAX_BODY = int(os.getenv("MAX_BODY_BYTES", "16384"))
DLR_MAP = {
    "DELIVRD": "delivered", "DELIVERED": "delivered",
    "SENT": "sent", "ACCEPTD": "accepted", "ACCEPTED": "accepted",
    "QUEUED": "queued", "SUBMITTED": "submitted",
    "UNDELIV": "failed", "FAILED": "failed", "ERROR": "failed",
    "REJECTD": "rejected", "REJECTED": "rejected",
    "EXPIRED": "expired",
}
GSM_BASIC = frozenset("@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà")
GSM_EXTENSION = frozenset("^{}\\[~]|€")


def telnexa_outbound_headers(body, *, timestamp=None, nonce=None):
    timestamp = str(int(time.time()) if timestamp is None else timestamp)
    nonce = uuid.uuid4().hex if nonce is None else nonce
    canonical = b"POST\n/v1/messages\n" + timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body
    signature = hmac.new(
        os.environ["TELNEXA_WEBHOOK_SECRET"].encode(), canonical, hashlib.sha256
    ).hexdigest()
    return {
        "Authorization": "Bearer " + os.environ["TELNEXA_MIDDLEWARE_API_KEY"],
        "Content-Type": "application/json",
        "X-Codestra-Timestamp": timestamp,
        "X-Codestra-Nonce": nonce,
        "X-Codestra-Signature": "sha256=" + signature,
    }


def db():
    if "db" not in g:
        g.db = psycopg.connect(os.environ["DATABASE_URL"], row_factory=dict_row, autocommit=True)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def error(code, message, status):
    return jsonify(error=code, message=message, correlation_id=request.headers.get("X-Correlation-ID")), status


@app.before_request
def bounds_and_identity():
    if request.content_length and request.content_length > MAX_BODY:
        return error("request_too_large", "request body exceeds limit", 413)
    if request.path in {"/health", "/livez", "/readyz", "/ready", "/metrics"} or request.path.startswith("/internal/"):
        return None
    supplied_gateway_token = request.headers.get("X-Codestra-Gateway-Token", "")
    supplied_digest = hashlib.sha256(supplied_gateway_token.encode("utf-8")).hexdigest()
    gateway_token_valid = hmac.compare_digest(supplied_digest, verifier("SMS_GATEWAY_TOKEN"))
    if os.getenv("SMS_GATEWAY_TOKEN_PREVIOUS_SHA256_FILE", ""):
        gateway_token_valid = gateway_token_valid or hmac.compare_digest(supplied_digest, verifier("SMS_GATEWAY_TOKEN_PREVIOUS"))
    if not gateway_token_valid:
        return error("unauthorized", "trusted Kong gateway required", 401)
    consumer_id = request.headers.get("X-Consumer-ID")
    if not consumer_id:
        return error("unauthorized", "Kong consumer identity required", 401)
    account = db().execute("SELECT * FROM sms_accounts WHERE kong_consumer_id=%s", (consumer_id,)).fetchone()
    if not account:
        return error("unauthorized", "consumer is not mapped to an SMS account", 401)
    g.account = account


def audit(event, message_id=None, detail=None, account_id=None, correlation_id=None):
    account = getattr(g, "account", None) or {}
    db().execute(
        "INSERT INTO sms_audit_events(account_id,event_type,message_id,correlation_id,detail) VALUES(%s,%s,%s,%s,%s)",
        (account_id or account.get("id"), event, message_id,
         correlation_id or request.headers.get("X-Correlation-ID"), json.dumps(detail or {})),
    )


def internal_event(conn, account, message, event_type, canonical_status, provider_status=None):
    event_id = uuid.uuid4()
    correlation_id = message.get("correlation_id") or "legacy-" + str(message["id"])
    payload = {
        "event_id": str(event_id), "event_type": event_type, "event_version": "1.0",
        "message_id": str(message["id"]), "customer_id": account["customer_code"],
        "customer_code": account["customer_code"], "correlation_id": correlation_id,
        "canonical_status": canonical_status, "provider_status": provider_status,
        "sender": message["sender"], "destination": message["destination"],
        "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "source": "sms",
        "retry": {"attempt": 0, "max_attempts": 5},
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    conn.execute(
        """INSERT INTO sms_internal_events
           (event_id,account_id,message_id,event_type,event_version,correlation_id,payload,envelope_hash)
           VALUES(%s,%s,%s,%s,'1.0',%s,%s,%s) ON CONFLICT(message_id,event_type) DO NOTHING""",
        (event_id, account["id"], message["id"], event_type, correlation_id, raw,
         hashlib.sha256(raw.encode()).hexdigest()),
    )


def segments(text):
    if all(c in GSM_BASIC or c in GSM_EXTENSION for c in text):
        units = sum(2 if c in GSM_EXTENSION else 1 for c in text)
        single, concat = 160, 153
    else:
        units = len(text.encode("utf-16-be")) // 2
        single, concat = 70, 67
    return 1 if units <= single else (units + concat - 1) // concat


def validate_carrier_submission(*, synthetic, live_delivery, receipt):
    """Fail closed unless provider delivery state matches the requested mode."""
    carrier_submitted = receipt.get("carrier_submitted")
    if not isinstance(carrier_submitted, bool):
        raise RuntimeError("provider omitted carrier submission state")
    expected = not synthetic and live_delivery
    if carrier_submitted is not expected:
        raise RuntimeError("provider carrier submission state violates delivery gate")
    return carrier_submitted


def global_rate_ok(conn):
    limit = int(os.getenv("GLOBAL_RATE_PER_MINUTE", "1000"))
    conn.execute("SELECT pg_advisory_xact_lock(%s)", (0x434F444553545241,))
    recent = conn.execute(
        "SELECT count(*) AS n FROM sms_messages WHERE created_at > now()-interval '1 minute'"
    ).fetchone()["n"]
    return recent < limit


@app.get("/health")
def health():
    db().execute("SELECT 1")
    return jsonify(status="ok", service="codestra-sms-api", live_submission=False)


@app.get("/livez")
def livez():
    return jsonify(status="alive", service="codestra-sms-api")


@app.get("/ready")
@app.get("/readyz")
def readyz():
    db().execute("SELECT 1")
    return jsonify(status="ready", service="codestra-sms-api", postgresql="ok", telnexa="disabled")


@app.get("/metrics")
def metrics():
    counts = {}
    for row in db().execute("SELECT event_type,count(*) n FROM sms_audit_events GROUP BY event_type"):
        counts[row["event_type"]] = row["n"]
    rejection_reasons = {
        row["reason"]: row["n"]
        for row in db().execute(
            "SELECT detail->>'reason' reason,count(*) n FROM sms_audit_events WHERE event_type='sms.denied' AND detail ? 'reason' GROUP BY detail->>'reason'"
        )
    }
    dlr = db().execute("SELECT count(*) n FROM sms_dlr_events").fetchone()["n"]
    dlq = db().execute("SELECT count(*) n FROM sms_dlr_dead_letters").fetchone()["n"]
    provisional = db().execute("SELECT count(*) n FROM sms_balance_ledger WHERE state='provisional'").fetchone()["n"]
    finalized = db().execute("SELECT count(*) n FROM sms_balance_ledger WHERE state='finalized'").fetchone()["n"]
    released = db().execute("SELECT count(*) n FROM sms_balance_ledger WHERE state='released'").fetchone()["n"]
    internal = list(db().execute("SELECT event_type,delivery_state,count(*) n,sum(attempt_count) retries FROM sms_internal_events GROUP BY event_type,delivery_state"))
    latency = db().execute("SELECT COALESCE(avg(extract(epoch from (delivered_at-created_at))),0) seconds FROM sms_internal_events WHERE delivered_at IS NOT NULL").fetchone()["seconds"]
    lines = [
        "# TYPE codestra_sms_audit_events_total counter",
        *[f'codestra_sms_audit_events_total{{event="{k}"}} {v}' for k, v in sorted(counts.items())],
        "# TYPE codestra_sms_rejected_total counter",
        *[f'codestra_sms_rejected_total{{reason="{k}"}} {v}' for k, v in sorted(rejection_reasons.items())],
        "# TYPE codestra_sms_dlr_received_total counter", f"codestra_sms_dlr_received_total {dlr}",
        "# TYPE codestra_sms_dlr_dead_letter_total gauge", f"codestra_sms_dlr_dead_letter_total {dlq}",
        "# TYPE codestra_sms_ledger_entries gauge",
        f'codestra_sms_ledger_entries{{state="provisional"}} {provisional}',
        f'codestra_sms_ledger_entries{{state="finalized"}} {finalized}',
        f'codestra_sms_ledger_entries{{state="released"}} {released}',
        "# TYPE codestra_sms_internal_events gauge",
        *[f'codestra_sms_internal_events{{event_type="{r["event_type"]}",state="{r["delivery_state"]}"}} {r["n"]}' for r in internal],
        "# TYPE codestra_sms_event_retries_total counter",
        *[f'codestra_sms_event_retries_total{{event_type="{r["event_type"]}"}} {r["retries"] or 0}' for r in internal],
        "# TYPE codestra_sms_event_delivery_latency_seconds gauge",
        f"codestra_sms_event_delivery_latency_seconds {latency}",
    ]
    return Response("\n".join(lines) + "\n", mimetype="text/plain")


@app.post("/messages")
def create_message():
    idem = request.headers.get("Idempotency-Key", "")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", idem):
        return error("invalid_idempotency_key", "valid Idempotency-Key required", 400)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("invalid_json", "JSON object required", 400)
    if set(data) - {"to", "from", "text", "synthetic"}:
        return error("unknown_fields", "carrier and route selection are not accepted", 400)
    destination, sender, content = str(data.get("to", "")), str(data.get("from", "")), str(data.get("text", ""))
    synthetic = data.get("synthetic") is True
    correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    canonical = json.dumps({"to": destination, "from": sender, "text": content, "synthetic": synthetic}, sort_keys=True, separators=(",", ":"))
    request_hash = hashlib.sha256(canonical.encode()).hexdigest()
    duplicate_hash = hashlib.sha256(f"{destination}\0{sender}\0{content}".encode()).hexdigest()
    conn = db()
    try:
        with conn.transaction():
            existing = conn.execute("SELECT * FROM sms_messages WHERE account_id=%s AND idempotency_key=%s FOR UPDATE", (g.account["id"], idem)).fetchone()
            if existing:
                if existing["request_hash"] != request_hash:
                    audit("sms.idempotency_conflict", existing["id"])
                    return error("idempotency_conflict", "key was used with a different request", 409)
                audit("sms.idempotent_replay", existing["id"])
                return jsonify(message_view(existing)), 200
            account = conn.execute("SELECT * FROM sms_accounts WHERE id=%s FOR UPDATE", (g.account["id"],)).fetchone()
            g.account = account
            if account["status"] != "active":
                audit("sms.denied", detail={"reason": "account_disabled"})
                return error("account_disabled", "account is not active", 403)
            if not account["sms_entitled"]:
                audit("sms.denied", detail={"reason": "not_entitled"})
                return error("sms_not_entitled", "SMS service is not enabled", 403)
            if synthetic and not account["customer_code"].startswith("SYNTHETIC-"):
                audit("sms.denied", detail={"reason": "synthetic_not_allowed"})
                return error("synthetic_not_allowed", "synthetic mode is restricted", 403)
            if not synthetic and os.getenv("LIVE_SUBMISSION_ENABLED", "false").lower() != "true":
                audit("sms.denied", detail={"reason": "live_submission_disabled"})
                return error("service_not_activated", "live SMS submission is disabled", 503)
            if not global_rate_ok(conn):
                audit("sms.denied", detail={"reason": "global_rate"})
                return error("global_rate_limited", "global SMS rate exceeded", 429)
            limit = conn.execute("SELECT * FROM sms_account_limits WHERE account_id=%s", (account["id"],)).fetchone()
            recent = conn.execute("SELECT count(*) AS n FROM sms_messages WHERE account_id=%s AND created_at > now()-interval '1 minute'", (account["id"],)).fetchone()["n"]
            if not limit or recent >= limit["messages_per_minute"]:
                audit("sms.denied", detail={"reason": "customer_rate"})
                return error("rate_limited", "customer SMS rate exceeded", 429)
            if not re.fullmatch(r"\+[1-9][0-9]{7,14}", destination):
                audit("sms.denied", detail={"reason": "destination"})
                return error("invalid_destination", "destination must be E.164", 422)
            route = conn.execute("SELECT * FROM sms_routes WHERE enabled AND %s LIKE destination_prefix || '%%' ORDER BY length(destination_prefix) DESC LIMIT 1", (destination,)).fetchone()
            if not route:
                audit("sms.denied", detail={"reason": "country_policy"})
                return error("destination_not_allowed", "destination/country is not enabled", 403)
            profile = conn.execute("SELECT * FROM sms_sender_profiles WHERE account_id=%s AND sender=%s AND status='active'", (account["id"], sender)).fetchone()
            if not profile:
                audit("sms.denied", detail={"reason": "sender"})
                return error("sender_not_authorized", "sender is not authorized", 403)
            if profile["sender_type"] == "alphanumeric" and not re.fullmatch(r"[A-Za-z0-9]{1,11}", sender):
                return error("invalid_sender", "alphanumeric sender rule failed", 422)
            if profile["sender_type"] in {"numeric", "shortcode"} and not re.fullmatch(r"[0-9]{3,15}", sender):
                return error("invalid_sender", "numeric sender rule failed", 422)
            if profile["country_codes"] and not any(destination.startswith(x) for x in profile["country_codes"]):
                return error("sender_country_denied", "sender is not approved for destination", 403)
            if conn.execute("SELECT 1 FROM sms_suppressions WHERE account_id=%s AND destination=%s AND active", (account["id"], destination)).fetchone():
                audit("sms.denied", detail={"reason": "suppressed"})
                return error("destination_suppressed", "destination is suppressed", 403)
            if not content or len(content) > 1000:
                return error("invalid_content", "text must contain 1-1000 characters", 422)
            segment_count = segments(content)
            if segment_count > limit["max_segments"]:
                return error("too_many_segments", "message exceeds account segment limit", 422)
            duplicate = conn.execute("SELECT * FROM sms_messages WHERE account_id=%s AND duplicate_hash=%s AND created_at > now()-(%s * interval '1 second') ORDER BY created_at DESC LIMIT 1", (account["id"], duplicate_hash, limit["duplicate_window_seconds"])).fetchone()
            if duplicate:
                audit("sms.duplicate", duplicate["id"], {"idempotency_key": idem})
                return jsonify(message_view(duplicate)), 200
            price = Decimal(route["unit_price"]) * segment_count
            if account["balance"] < price:
                audit("sms.denied", detail={"reason": "balance"})
                return error("insufficient_balance", "account balance is insufficient", 402)
            adapter_payload = {
                "customer_id": account["customer_code"], "sender": profile["provider_sender"],
                "to": destination, "body": content, "idempotency_key": idem,
                "correlation_id": correlation_id,
            }
            adapter_started = time.monotonic()
            try:
                adapter_body = json.dumps(adapter_payload, separators=(",", ":")).encode()
                adapter = requests.post(
                    os.environ["TELNEXA_BASE_URL"].rstrip("/") + "/v1/messages",
                    headers=telnexa_outbound_headers(adapter_body),
                    data=adapter_body,
                    cert=(os.environ["TELNEXA_CLIENT_CERT_FILE"], os.environ["TELNEXA_CLIENT_KEY_FILE"]),
                    verify=os.environ["TELNEXA_CA_FILE"],
                    timeout=3,
                )
                adapter_receipt = adapter.json()
                if adapter.status_code not in {200, 202} or not adapter_receipt.get("accepted"):
                    raise RuntimeError("restricted adapter rejected gated submission")
                carrier_submitted = validate_carrier_submission(
                    synthetic=synthetic,
                    live_delivery=os.getenv("LIVE_SMS_DELIVERY", "false").lower() == "true",
                    receipt=adapter_receipt,
                )
            except (requests.RequestException, ValueError, RuntimeError, KeyError):
                audit("sms.adapter_unavailable", detail={"route_id": str(route["id"]), "latency_ms": round((time.monotonic() - adapter_started) * 1000, 2)})
                return error("upstream_unavailable", "restricted Telnexa adapter unavailable", 503)
            message_id = uuid.uuid4()
            row = conn.execute(
                """INSERT INTO sms_messages(id,account_id,idempotency_key,request_hash,duplicate_hash,destination,sender,content,segments,route_id,status,synthetic,total_price,currency,adapter_message_id,correlation_id,carrier_submitted)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'accepted',%s,%s,%s,%s,%s,%s) RETURNING *""",
                (message_id, account["id"], idem, request_hash, duplicate_hash, destination, sender, content,
                 segment_count, route["id"], synthetic, price, route["currency"], adapter_receipt["adapter_message_id"], correlation_id, carrier_submitted),
            ).fetchone()
            new_balance = account["balance"] - price
            conn.execute("UPDATE sms_accounts SET balance=%s WHERE id=%s", (new_balance, account["id"]))
            conn.execute(
                """INSERT INTO sms_balance_ledger(account_id,message_id,entry_type,amount,balance_after,destination,sender,route_id,segments,unit_price,total_price,currency,submitted_at,final_status,state)
                   VALUES(%s,%s,'reservation',%s,%s,%s,%s,%s,%s,%s,%s,%s,now(),'provisional','provisional')""",
                (account["id"], message_id, -price, new_balance, destination, sender, route["id"], segment_count, route["unit_price"], price, route["currency"]),
            )
            attempt_outcome = "carrier_submitted" if carrier_submitted else "restricted_accepted"
            conn.execute("INSERT INTO sms_message_attempts(message_id,attempt_no,route_id,outcome,provider_response) VALUES(%s,1,%s,%s,%s)", (message_id, route["id"], attempt_outcome, json.dumps(adapter_receipt)))
            internal_event(conn, account, row, "sms.submitted", "submitted")
            audit("sms.submitted", message_id, {"synthetic": synthetic, "route_id": str(route["id"]), "carrier_submitted": carrier_submitted, "telnexa_latency_ms": round((time.monotonic() - adapter_started) * 1000, 2)})
        return jsonify(message_view(row)), 202
    except psycopg.Error:
        conn.rollback()
        app.logger.exception("database error")
        return error("internal_error", "request could not be processed", 500)


def message_view(row):
    return {
        "message_id": str(row["id"]), "to": row["destination"], "from": row["sender"],
        "status": row["status"], "provider_status": row["provider_status"],
        "segments": row["segments"], "total_price": str(row["total_price"]),
        "currency": row["currency"], "synthetic": row["synthetic"],
        "carrier_submitted": row.get("carrier_submitted", False),
        "correlation_id": row.get("correlation_id"), "created_at": row["created_at"].isoformat(),
    }


def owned_message(message_id):
    try:
        parsed = uuid.UUID(message_id)
    except ValueError:
        return None
    return db().execute("SELECT * FROM sms_messages WHERE id=%s AND account_id=%s", (parsed, g.account["id"])).fetchone()


@app.get("/messages/<message_id>")
def get_message(message_id):
    row = owned_message(message_id)
    return (jsonify(message_view(row)), 200) if row else error("not_found", "message not found", 404)


@app.get("/messages/<message_id>/status")
def get_status(message_id):
    row = owned_message(message_id)
    return (jsonify(message_id=str(row["id"]), status=row["status"], provider_status=row["provider_status"], updated_at=row["updated_at"].isoformat()), 200) if row else error("not_found", "message not found", 404)


def verify_dlr(raw_body):
    authorization = request.headers.get("Authorization", "")
    if not hmac.compare_digest(authorization, "Bearer " + os.environ["SMS_DLR_TOKEN"]):
        return "invalid DLR credential"
    timestamp = request.headers.get("X-Telnexa-Timestamp", "")
    event_id = request.headers.get("X-Telnexa-Event-Id", "")
    signature = request.headers.get("X-Telnexa-Signature", "").removeprefix("sha256=")
    source = request.headers.get("X-Source-System", "")
    try:
        if source != "telnexa" or abs(int(time.time()) - int(timestamp)) > 300:
            return "invalid DLR signature context"
    except ValueError:
        return "invalid DLR signature context"
    canonical = timestamp.encode() + b"\n" + event_id.encode() + b"\n" + source.encode() + b"\n" + raw_body
    expected = hmac.new(os.environ["TELNEXA_WEBHOOK_SECRET"].encode(), canonical, hashlib.sha256).hexdigest()
    if not event_id or not re.fullmatch(r"[0-9a-f]{64}", signature) or not hmac.compare_digest(expected, signature):
        return "invalid DLR signature"
    return None


def dead_letter(data, payload_hash, reason):
    db().execute(
        """INSERT INTO sms_dlr_dead_letters(provider_event_id,payload_hash,provider_message_id,adapter_message_id,middleware_message_id,customer_code,correlation_id,provider_status,reason,raw_payload)
           VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (data.get("event_id"), payload_hash, data.get("provider_message_id"), data.get("adapter_message_id"),
         data.get("message_id"), data.get("customer_id"), data.get("correlation_id"), data.get("status"), reason, json.dumps(data)),
    )
    audit("sms.dlr_dead_letter", detail={"reason": reason}, correlation_id=data.get("correlation_id"))


@app.post("/internal/dlr")
def dlr():
    raw_body = request.get_data(cache=True)
    auth_error = verify_dlr(raw_body)
    if auth_error:
        return error("unauthorized", auth_error, 401)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("invalid_json", "JSON object required", 400)
    event_id = str(data.get("event_id", ""))
    if event_id != request.headers.get("X-Telnexa-Event-Id") or not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", event_id):
        return error("invalid_event_id", "valid matching event ID required", 422)
    raw_status = str(data.get("status", "UNKNOWN")).upper()
    canonical_status = DLR_MAP.get(raw_status, "unknown")
    payload_hash = hashlib.sha256(raw_body).hexdigest()
    conn = db()
    with conn.transaction():
        prior = conn.execute("SELECT * FROM sms_dlr_events WHERE provider_event_id=%s FOR UPDATE", (event_id,)).fetchone()
        if prior:
            if prior["payload_hash"] == payload_hash:
                audit("sms.dlr_duplicate", prior["message_id"], correlation_id=prior["correlation_id"])
                return jsonify(accepted=True, duplicate=True, message_id=str(prior["message_id"]), status=prior["canonical_status"]), 200
            dead_letter(data, payload_hash, "conflicting_duplicate_event_id")
            return error("dlr_conflict", "event ID was reused with different content", 409)
        message = None
        supplied_message_id = str(data.get("message_id", ""))
        adapter_message_id = str(data.get("adapter_message_id", ""))
        provider_message_id = str(data.get("provider_message_id", ""))
        if supplied_message_id:
            try:
                message = conn.execute("SELECT * FROM sms_messages WHERE id=%s FOR UPDATE", (uuid.UUID(supplied_message_id),)).fetchone()
            except ValueError:
                message = None
        if not message and adapter_message_id:
            message = conn.execute("SELECT * FROM sms_messages WHERE adapter_message_id=%s FOR UPDATE", (adapter_message_id,)).fetchone()
        if not message and provider_message_id:
            message = conn.execute("SELECT * FROM sms_messages WHERE provider_message_id=%s FOR UPDATE", (provider_message_id,)).fetchone()
        if not message:
            dead_letter(data, payload_hash, "uncorrelated_message")
            return error("not_found", "DLR message correlation failed", 404)
        account = conn.execute("SELECT * FROM sms_accounts WHERE id=%s", (message["account_id"],)).fetchone()
        checks = [
            (adapter_message_id and adapter_message_id != (message["adapter_message_id"] or ""), "adapter_message_id_mismatch"),
            (data.get("customer_id") and data["customer_id"] != account["customer_code"], "customer_mismatch"),
            (data.get("correlation_id") and data["correlation_id"] != message["correlation_id"], "correlation_mismatch"),
            (provider_message_id and message["provider_message_id"] and provider_message_id != message["provider_message_id"], "provider_message_id_mismatch"),
        ]
        mismatch = next((reason for failed, reason in checks if failed), None)
        if mismatch:
            dead_letter(data, payload_hash, mismatch)
            return error("dlr_correlation_conflict", "DLR identifiers do not match", 409)
        conn.execute(
            """INSERT INTO sms_dlr_events(message_id,provider_event_id,canonical_status,provider_status,raw_payload,payload_hash,adapter_message_id,customer_id,correlation_id,processing_state)
               VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'processed')""",
            (message["id"], event_id, canonical_status, raw_status, json.dumps(data), payload_hash,
             message["adapter_message_id"], message["account_id"], message["correlation_id"]),
        )
        rank = {"accepted": 10, "queued": 20, "submitted": 30, "sent": 40, "failed": 50, "rejected": 50, "expired": 50, "delivered": 60}
        current_rank = rank.get(message["status"], 0)
        next_rank = rank.get(canonical_status, 0)
        stale = next_rank < current_rank or (message["status"] == "delivered" and canonical_status != "delivered")
        if not stale:
            conn.execute("UPDATE sms_messages SET status=%s,provider_status=%s,provider_message_id=COALESCE(provider_message_id,%s),updated_at=now() WHERE id=%s", (canonical_status, raw_status, provider_message_id or None, message["id"]))
        else:
            audit("sms.dlr_stale", message["id"], {"current_status": message["status"], "ignored_status": canonical_status}, message["account_id"], message["correlation_id"])
        ledger = conn.execute("SELECT * FROM sms_balance_ledger WHERE message_id=%s FOR UPDATE", (message["id"],)).fetchone()
        if ledger and message["carrier_submitted"]:
            if canonical_status in {"sent", "delivered"} and ledger["state"] == "provisional":
                conn.execute("UPDATE sms_balance_ledger SET state='finalized',entry_type='debit',final_status=%s,finalized_at=now() WHERE id=%s", (canonical_status, ledger["id"]))
            elif canonical_status in {"failed", "rejected", "expired"} and ledger["state"] == "provisional":
                updated = conn.execute("UPDATE sms_accounts SET balance=balance+%s WHERE id=%s RETURNING balance", (-ledger["amount"], message["account_id"])).fetchone()
                conn.execute("UPDATE sms_balance_ledger SET state='released',entry_type='release',amount=0,balance_after=%s,final_status=%s,released_at=now() WHERE id=%s", (updated["balance"], canonical_status, ledger["id"]))
        elif ledger:
            conn.execute("UPDATE sms_balance_ledger SET final_status=%s WHERE id=%s", ("provisional", ledger["id"]))
        business_event = {value: "sms." + value for value in ("sent", "delivered", "failed", "rejected", "expired")}.get(canonical_status)
        if business_event and not stale:
            internal_event(conn, account, message, business_event, canonical_status, raw_status)
        audit("sms.dlr_correlated", message["id"], {"status": canonical_status}, message["account_id"], message["correlation_id"])
    return jsonify(accepted=True, duplicate=False, message_id=str(message["id"]), status=canonical_status, provider_status=raw_status), 200
