import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = os.getenv("INTEGRATION_DB", "/data/integration.db")
MODE = os.getenv("GATEWAY_MODE", "middleware")
TTL = int(os.getenv("WEBHOOK_TTL_SECONDS", "300"))
MAX_BODY = int(os.getenv("MAX_BODY_BYTES", "262144"))
logging.basicConfig(level=logging.INFO, format="%(asctime)s level=%(levelname)s %(message)s")

SYSTEMS = {
    "kyqra": ("KYQRA_MIDDLEWARE_API_KEY", "KYQRA_WEBHOOK_SECRET", "X-Kyqra"),
    "telnexa": ("TELNEXA_MIDDLEWARE_API_KEY", "TELNEXA_WEBHOOK_SECRET", "X-Telnexa"),
    "klyrow": ("KLYROW_MIDDLEWARE_API_KEY", "KLYROW_WEBHOOK_SECRET", "X-Klyrow"),
}
KYQRA_PATHS = {"/api/v1/kyqra/jobs", "/api/v1/kyqra/results", "/api/v1/kyqra/progress", "/api/v1/kyqra/failures"}
TELNEXA_PATHS = {"/api/v1/telnexa/inbound", "/api/v1/telnexa/dlr", "/api/v1/telnexa/failure", "/api/v1/telnexa/provider-status"}
KLYROW_PATHS = {"/api/v1/klyrow/campaigns", "/api/v1/klyrow/contacts", "/api/v1/klyrow/events", "/api/v1/klyrow/bounces", "/api/v1/klyrow/complaints", "/api/v1/klyrow/unsubscribes"}
EVENT_TYPES = {
    "/api/v1/kyqra/results": "kyqra.record.created",
    "/api/v1/kyqra/progress": "kyqra.job.completed",
    "/api/v1/telnexa/inbound": "telnexa.sms.received",
    "/api/v1/telnexa/dlr": "telnexa.sms.delivered",
    "/api/v1/telnexa/failure": "telnexa.sms.failed",
    "/api/v1/klyrow/events": "klyrow.email.event",
    "/api/v1/klyrow/bounces": "klyrow.email.bounced",
    "/api/v1/klyrow/complaints": "klyrow.email.complained",
    "/api/v1/klyrow/unsubscribes": "klyrow.email.unsubscribed",
}
READY_EVENTS_SQL = "SELECT * FROM events WHERE state='queued' AND next_attempt<=? ORDER BY created_at ASC LIMIT 20"

def db():
    conn = sqlite3.connect(DB, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def initialize():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    with db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS events(event_id TEXT PRIMARY KEY, system TEXT NOT NULL, path TEXT NOT NULL, entity_key TEXT, payload TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0, created_at REAL NOT NULL, last_error TEXT)")
        conn.execute("DROP INDEX IF EXISTS kyqra_record_unique")
        conn.execute("CREATE UNIQUE INDEX kyqra_record_unique ON events(system, entity_key) WHERE system='kyqra' AND path='/api/v1/kyqra/results' AND entity_key IS NOT NULL")
        conn.execute("CREATE TABLE IF NOT EXISTS outbound(idempotency_key TEXT PRIMARY KEY, payload TEXT NOT NULL, state TEXT NOT NULL, created_at REAL NOT NULL)")

def canonical(timestamp, event_id, source, body):
    return timestamp.encode() + b"\n" + event_id.encode() + b"\n" + source.encode() + b"\n" + body

def entity_key(system, path, payload):
    if system == "kyqra" and path == "/api/v1/kyqra/results":
        return str(payload.get("record_id") or "") or None
    return str(payload.get("message_id") or payload.get("job_id") or "") or None

def mock_adapter_receipt(payload, duplicate):
    adapter_message_id = "mock-" + hashlib.sha256(payload["idempotency_key"].encode()).hexdigest()[:24]
    return {"accepted": True, "duplicate": duplicate, "carrier_submitted": False,
            "state": "mock_accepted", "adapter_message_id": adapter_message_id}

def worker():
    while True:
        try:
            with db() as conn:
                rows = conn.execute(READY_EVENTS_SQL, (time.time(),)).fetchall()
            for row in rows:
                deliver(row)
        except Exception as exc:
            logging.error("system=gateway worker_error=%s", type(exc).__name__)
        time.sleep(1)

def deliver(row):
    target = os.getenv("DOWNSTREAM_CONTROL_PLANE_URL", "").strip().rstrip("/")
    if not target:
        return
    payload = json.loads(row["payload"])
    try:
        tenant_id = str(payload.get("tenant_id") or "").strip()
        correlation_id = str(payload.get("correlation_id") or "").strip()
        if not tenant_id or not correlation_id:
            raise ValueError("missing governed event context")
        envelope = {
            "event_type": EVENT_TYPES.get(row["path"], row["path"].rsplit("/", 1)[-1]),
            "event_version": "1.0",
            "occurred_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tenant_id": tenant_id,
            "customer_id": payload.get("customer_id"),
            "correlation_id": correlation_id,
            # A provider message has multiple immutable lifecycle events. Key
            # downstream idempotency by the immutable event ID so a held event
            # cannot suppress the later delivered/bounced terminal event.
            "idempotency_key": "gateway:%s:%s" % (row["system"], row["event_id"]),
            "payload": payload,
            "metadata": {"private_gateway": True},
        }
        body = json.dumps(envelope, separators=(",", ":")).encode()
        key_name, secret_name, _ = SYSTEMS[row["system"]]
        api_key, secret = os.getenv(key_name, ""), os.getenv(secret_name, "")
        if not api_key or not secret:
            raise ValueError("missing downstream credentials")
        timestamp = str(int(time.time()))
        signature = hmac.new(secret.encode(), canonical(timestamp, row["event_id"], row["system"], body), hashlib.sha256).hexdigest()
        headers = {
            "Content-Type": "application/json", "Authorization": "Bearer " + api_key,
            "X-Event-Id": row["event_id"], "X-Timestamp": timestamp,
            "X-Signature": "sha256=" + signature,
        }
        req = urllib.request.Request(target + "/" + row["system"], body, headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status >= 300: raise RuntimeError("downstream status")
        with db() as conn: conn.execute("UPDATE events SET state='delivered',last_error=NULL WHERE event_id=?", (row["event_id"],))
    except Exception as exc:
        attempts = row["attempts"] + 1
        state = "dead_letter" if attempts >= 5 else "queued"
        delay = min(60, 2 ** attempts)
        with db() as conn: conn.execute("UPDATE events SET state=?,attempts=?,next_attempt=?,last_error=? WHERE event_id=?", (state, attempts, time.time()+delay, type(exc).__name__, row["event_id"]))
        logging.warning("system=%s event_id=%s callback_failure=%s attempts=%d", row["system"], row["event_id"], type(exc).__name__, attempts)

class Handler(BaseHTTPRequestHandler):
    server_version = "PrivateIntegrationGateway/1.0"
    def log_message(self, fmt, *args): logging.info("system=http client=%s " + fmt, self.client_address[0], *args)
    def send_json(self, code, value):
        raw = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        if self.path == "/livez":
            return self.send_json(200, {"status":"alive", "service":"private-integration-gateway"})
        if self.path in {"/ready", "/readyz"}:
            try:
                with db() as conn: conn.execute("SELECT 1").fetchone()
            except (OSError, sqlite3.Error):
                return self.send_json(503, {"status":"not_ready", "service":"private-integration-gateway"})
            return self.send_json(200, {"status":"ready", "service":"private-integration-gateway", "required_dependencies":"online"})
        if self.path in {"/health", "/healthz", "/api/v1/kyqra/health", "/api/v1/telnexa/health", "/api/v1/klyrow/health"}:
            return self.send_json(200, {"status":"ok", "mode":MODE})
        if self.path == "/metrics":
            with db() as conn:
                rows = conn.execute("SELECT system,state,count(*) n FROM events GROUP BY system,state").fetchall()
            return self.send_json(200, {"events":[dict(r) for r in rows]})
        self.send_json(404, {"detail":"not found"})
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY: return self.send_json(413, {"detail":"invalid body size"})
        body = self.rfile.read(length)
        if MODE == "shared" and self.path == "/v1/messages": return self.outbound(body)
        system = "kyqra" if self.path in KYQRA_PATHS else "telnexa" if self.path in TELNEXA_PATHS else "klyrow" if self.path in KLYROW_PATHS else None
        if MODE != "middleware" or not system: return self.send_json(404, {"detail":"not found"})
        return self.ingress(system, body)
    def authenticate_key(self, system):
        key_name, _, _ = SYSTEMS[system]; expected = os.getenv(key_name, "")
        supplied = self.headers.get("Authorization", "")
        return bool(expected) and hmac.compare_digest(supplied.encode(), ("Bearer " + expected).encode())
    def ingress(self, system, body):
        if not self.authenticate_key(system): return self.send_json(401, {"detail":"invalid api key"})
        _, secret_name, prefix = SYSTEMS[system]
        timestamp = self.headers.get(prefix+"-Timestamp", ""); event_id = self.headers.get(prefix+"-Event-Id", ""); signature = self.headers.get(prefix+"-Signature", "")
        source = self.headers.get("X-Source-System", "")
        if not timestamp or not event_id or not signature or source != system: return self.send_json(401, {"detail":"missing authentication headers"})
        try: ts = int(timestamp)
        except ValueError: return self.send_json(401, {"detail":"invalid timestamp"})
        if abs(int(time.time()) - ts) > TTL: return self.send_json(401, {"detail":"expired timestamp"})
        secret = os.getenv(secret_name, "")
        expected = hmac.new(secret.encode(), canonical(timestamp,event_id,source,body), hashlib.sha256).hexdigest()
        supplied = signature.removeprefix("sha256=")
        if not secret or not hmac.compare_digest(supplied, expected): return self.send_json(401, {"detail":"invalid signature"})
        try: payload = json.loads(body)
        except json.JSONDecodeError: return self.send_json(422, {"detail":"invalid json"})
        required = {"job_id","record_id","source_url","business_name","crawl_timestamp"} if self.path == "/api/v1/kyqra/results" else set()
        if required - payload.keys(): return self.send_json(422, {"detail":"missing required fields", "fields":sorted(required-payload.keys())})
        key = entity_key(system, self.path, payload)
        try:
            with db() as conn: conn.execute("INSERT INTO events(event_id,system,path,entity_key,payload,state,created_at) VALUES(?,?,?,?,?,'queued',?)", (event_id,system,self.path,key,json.dumps(payload,separators=(",",":")),time.time()))
        except sqlite3.IntegrityError:
            with db() as conn: replay = conn.execute("SELECT 1 FROM events WHERE event_id=?", (event_id,)).fetchone() is not None
            if replay: return self.send_json(409, {"accepted":False,"detail":"replayed event id","event_id":event_id})
            return self.send_json(200, {"accepted":True,"duplicate":True,"event_id":event_id})
        logging.info("system=%s event_id=%s job_id=%s message_id=%s customer_id=%s accepted=true", system,event_id,payload.get("job_id","-"),payload.get("message_id","-"),payload.get("customer_id","-"))
        self.send_json(202, {"accepted":True,"duplicate":False,"event_id":event_id})
    def outbound(self, body):
        if not self.authenticate_key("telnexa"): return self.send_json(401, {"detail":"invalid api key"})
        try: payload=json.loads(body)
        except json.JSONDecodeError: return self.send_json(422,{"detail":"invalid json"})
        needed={"customer_id","to","body","idempotency_key"}
        if needed-payload.keys(): return self.send_json(422,{"detail":"missing required fields","fields":sorted(needed-payload.keys())})
        try:
            with db() as conn: conn.execute("INSERT INTO outbound VALUES(?,?,'mock_accepted',?)",(payload["idempotency_key"],json.dumps(payload,separators=(",",":")),time.time()))
            duplicate=False
        except sqlite3.IntegrityError: duplicate=True
        logging.info("system=telnexa idempotency_key=%s customer_id=%s outbound_mock=true",payload["idempotency_key"],payload["customer_id"])
        self.send_json(202, mock_adapter_receipt(payload, duplicate))

if __name__ == "__main__":
    initialize()
    threading.Thread(target=worker, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
