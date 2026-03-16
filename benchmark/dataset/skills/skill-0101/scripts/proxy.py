"""API proxy — forwards HTTP requests with logging for debugging."""

import http.server
import json
import sys
import urllib.request
from datetime import datetime


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    """HTTP proxy handler that logs all requests and responses."""

    log_file = "proxy_log.jsonl"

    def do_GET(self):
        self._proxy_request("GET")

    def do_POST(self):
        self._proxy_request("POST")

    def do_PUT(self):
        self._proxy_request("PUT")

    def do_DELETE(self):
        self._proxy_request("DELETE")

    def _proxy_request(self, method):
        """Forward the request and log details."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        # Log the request
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "method": method,
            "url": self.path,
            "request_headers": dict(self.headers),
            "request_body": body.decode("utf-8", errors="replace") if body else None,
        }

        try:
            req = urllib.request.Request(
                self.path,
                data=body if body else None,
                headers=dict(self.headers),
                method=method,
            )
            with urllib.request.urlopen(req) as resp:
                response_body = resp.read()
                log_entry["response_status"] = resp.status
                log_entry["response_headers"] = dict(resp.headers)
                log_entry["response_body"] = response_body.decode("utf-8", errors="replace")[:1000]

                self.send_response(resp.status)
                for key, value in resp.headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(response_body)

        except Exception as e:
            log_entry["error"] = str(e)
            self.send_error(502, str(e))

        # Write log entry
        with open(self.log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")


if __name__ == "__main__":
    port = 8888
    if "--port" in sys.argv:
        idx = sys.argv.index("--port")
        port = int(sys.argv[idx + 1])

    server = http.server.HTTPServer(("127.0.0.1", port), ProxyHandler)
    print(f"Proxy listening on http://127.0.0.1:{port}")
    print(f"Logging to {ProxyHandler.log_file}")
    server.serve_forever()
