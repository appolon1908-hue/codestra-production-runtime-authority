import asyncio, hashlib, hmac, json, logging, os, sqlite3, time
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict

DB="/data/alerts.db"; SECRET=open("/run/secrets/hmac","rb").read().strip()
BEARER=open("/run/secrets/bearer","rb").read().strip()
logging.basicConfig(format='{"level":"%(levelname)s","message":"%(message)s"}',level=logging.INFO)
logger=logging.getLogger("codestra.receiver")
app=FastAPI()
class Alert(BaseModel):
    model_config=ConfigDict(extra="forbid")
    version:str
    groupKey:str
    status:str
    alerts:list[dict]
    receiver:str|None=None
    truncatedAlerts:int|None=None
    groupLabels:dict[str,str]|None=None
    commonLabels:dict[str,str]|None=None
    commonAnnotations:dict[str,str]|None=None
    externalURL:str|None=None
    notification_reason:str|None=None

def db():
    c=sqlite3.connect(DB); c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY,route TEXT,status TEXT,body_hash TEXT,created INTEGER,ack INTEGER DEFAULT 0)")
    c.execute("CREATE TABLE IF NOT EXISTS replay(nonce TEXT PRIMARY KEY,created INTEGER)")
    c.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,action TEXT,result TEXT,reference TEXT,created INTEGER)")
    c.execute("CREATE TABLE IF NOT EXISTS requests(created INTEGER)")
    return c
async def escalation_worker():
    while True:
        now=int(time.time())
        with db() as c:
            rows=c.execute("SELECT id,status,body_hash,created FROM alerts WHERE route='primary' AND ack=0 AND created<=?",(now-900,)).fetchall()
            for row in rows:
                escalation_id="escalation-"+row[0]
                inserted=c.execute("INSERT OR IGNORE INTO alerts(id,route,status,body_hash,created) VALUES(?,?,?,?,?)",(escalation_id,"secondary",row[1],row[2],now)).rowcount
                if inserted: c.execute("INSERT INTO audit(action,result,reference,created) VALUES(?,?,?,?)",("escalate","secondary",row[0],now))
        await asyncio.sleep(5)
@app.on_event("startup")
async def start_worker():
    asyncio.create_task(escalation_worker())
@app.get("/healthz")
def health(): return {"status":"ok"}
@app.get("/readyz")
def ready():
    with db() as c: c.execute("SELECT 1")
    return {"status":"ready"}
@app.post("/api/v1/alerts/{route}")
async def receive(route:str, request:Request, authorization:str|None=Header(None), x_codestra_timestamp:str|None=Header(None), x_codestra_nonce:str|None=Header(None), x_codestra_signature:str|None=Header(None)):
    if route not in {"primary","secondary","recovery","rejected-route"}: raise HTTPException(404)
    body=await request.body()
    if len(body)>262144: raise HTTPException(413)
    bearer_ok=bool(authorization and authorization.startswith("Bearer ") and hmac.compare_digest(authorization[7:].encode(),BEARER))
    if not bearer_ok:
        if not all((x_codestra_timestamp,x_codestra_nonce,x_codestra_signature)): raise HTTPException(401)
        try: ts=int(x_codestra_timestamp)
        except ValueError: raise HTTPException(401)
        if abs(time.time()-ts)>300: raise HTTPException(401)
        expected=hmac.new(SECRET,x_codestra_timestamp.encode()+b"."+x_codestra_nonce.encode()+b"."+body,hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected,x_codestra_signature): raise HTTPException(401)
    try: alert=Alert.model_validate_json(body)
    except Exception:
        try: logger.warning("schema rejected keys=%s",sorted(json.loads(body).keys()))
        except Exception: logger.warning("schema rejected malformed_json")
        raise HTTPException(422)
    digest=hashlib.sha256(body).hexdigest(); nonce=x_codestra_nonce or digest
    ident=hashlib.sha256((route+nonce+digest).encode()).hexdigest()
    with db() as c:
        now=int(time.time()); c.execute("DELETE FROM requests WHERE created<?",(now-60,))
        if c.execute("SELECT count(*) FROM requests").fetchone()[0]>=60: raise HTTPException(429)
        c.execute("INSERT INTO requests VALUES(?)",(now,))
        if not bearer_ok:
            try: c.execute("INSERT INTO replay VALUES(?,?)",(nonce,now))
            except sqlite3.IntegrityError: raise HTTPException(409)
        c.execute("INSERT OR IGNORE INTO alerts(id,route,status,body_hash,created) VALUES(?,?,?,?,?)",(ident,route,alert.status,digest,int(time.time())))
        c.execute("INSERT INTO audit(action,result,reference,created) VALUES(?,?,?,?)",("receive","accepted",ident,now))
    logger.info("alert accepted route=%s reference=%s",route,ident)
    return {"accepted":True,"id":ident}
def require_bearer(authorization:str|None):
    if not authorization or not authorization.startswith("Bearer ") or not hmac.compare_digest(authorization[7:].encode(),BEARER):
        raise HTTPException(401)
@app.post("/api/v1/alerts/{alert_id}/ack")
def ack(alert_id:str,authorization:str|None=Header(None)):
    require_bearer(authorization)
    with db() as c:
        n=c.execute("UPDATE alerts SET ack=1 WHERE id=?",(alert_id,)).rowcount
        c.execute("INSERT INTO audit(action,result,reference,created) VALUES(?,?,?,?)",("ack","acknowledged",alert_id,int(time.time())))
    if not n: raise HTTPException(404)
    return {"acknowledged":True}
@app.get("/api/v1/alerts/{alert_id}")
def status(alert_id:str,authorization:str|None=Header(None)):
    require_bearer(authorization)
    with db() as c: row=c.execute("SELECT route,status,ack,created FROM alerts WHERE id=?",(alert_id,)).fetchone()
    if not row: raise HTTPException(404)
    return {"route":row[0],"status":row[1],"acknowledged":bool(row[2]),"created":row[3]}
@app.get("/api/v1/dashboard")
def dashboard(authorization:str|None=Header(None)):
    require_bearer(authorization)
    with db() as c:
        rows=c.execute("SELECT route,status,ack,count(*) FROM alerts GROUP BY route,status,ack").fetchall()
    return {"status":"ok","series":[{"route":r[0],"alert_status":r[1],"acknowledged":bool(r[2]),"count":r[3]} for r in rows]}
