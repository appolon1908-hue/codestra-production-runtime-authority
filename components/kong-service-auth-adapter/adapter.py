import http.client
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MAX_BODY = 1024 * 1024
ROUTES = {
    "/sms": {
        "host": "codestra-sms-api-api-1",
        "port": 8080,
        "prefix": "",
        "header": "X-Codestra-Gateway-Token",
        "secret_file": "/run/secrets/sms_gateway_token",
    },
    "/crm": {
        "host": "codestra-integration-control-plane-api-1",
        "port": 8096,
        "prefix": "/v1/crm",
        "header": "X-Codestra-Crm-Gateway-Secret",
        "secret_file": "/run/secrets/crm_gateway_secret",
    },
}


def read_secret(path):
    with open(path, "r", encoding="utf-8") as handle:
        value = handle.read().strip()
    if len(value) < 32:
        raise RuntimeError("invalid secret material")
    return value


SECRETS = {name: read_secret(config["secret_file"]) for name, config in ROUTES.items()}


class Handler(BaseHTTPRequestHandler):
    server_version = "CodestraServiceAuthAdapter/1"
    sys_version = ""

    def log_message(self, fmt, *args):
        # Deliberately omit paths and all request metadata; headers are never logged.
        return

    def send_safe(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def route(self):
        path_only = self.path.split("?", 1)[0]
        for base, config in ROUTES.items():
            if path_only == base or path_only.startswith(base + "/"):
                suffix = self.path[len(base):]
                return base, config, config["prefix"] + (suffix or "/")
        return None

    def proxy(self):
        if self.path == "/healthz":
            return self.send_safe(200, b"ok\n")
        selected = self.route()
        if not selected:
            return self.send_safe(404, b"not found\n")
        base, config, upstream_path = selected
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.send_safe(400, b"bad request\n")
        if length > MAX_BODY:
            return self.send_safe(413, b"request too large\n")
        body = self.rfile.read(length) if length else None
        blocked = {"host", "content-length", "connection", config["header"].lower()}
        headers = {key: value for key, value in self.headers.items() if key.lower() not in blocked}
        headers[config["header"]] = SECRETS[base]
        headers["Host"] = config["host"]
        try:
            connection = http.client.HTTPConnection(config["host"], config["port"], timeout=10)
            connection.request(self.command, upstream_path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in {"connection", "transfer-encoding", "content-length", "server", "date"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
        except Exception:
            self.send_safe(502, b"upstream unavailable\n")
        finally:
            try:
                connection.close()
            except Exception:
                pass

    do_GET = proxy
    do_HEAD = proxy
    do_POST = proxy
    do_PUT = proxy
    do_PATCH = proxy
    do_DELETE = proxy
    do_OPTIONS = proxy


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.getenv("PORT", "8080"))), Handler).serve_forever()
