"""Loopback HTTP fixture: expose the proxy's actual request, not a canned response."""

import json
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        response = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "body": body.decode(),
                "headers": dict(self.headers),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


server = ThreadingHTTPServer(
    ("127.0.0.1", 8444 if len(sys.argv) > 1 else 8080), Handler
)
if len(sys.argv) > 1:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(sys.argv[1], sys.argv[2])
    server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
