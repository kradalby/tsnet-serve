"""Loopback HTTP fixture: expose the proxy's actual request, not a canned response."""

import json
import ssl
import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if urlsplit(self.path).path.endswith(".txt"):
            super().do_GET()
        else:
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


with TemporaryDirectory() as directory:
    for name, body in {
        "allowed/public/hello.txt": "allowed resource\n",
        "allowed/private/secret.txt": "private resource\n",
        "outside.txt": "outside resource\n",
    }.items():
        resource = Path(directory, name)
        resource.parent.mkdir(parents=True, exist_ok=True)
        resource.write_text(body)
    server = ThreadingHTTPServer(
        ("127.0.0.1", 8444 if len(sys.argv) > 1 else 8080),
        partial(Handler, directory=directory),
    )
    if len(sys.argv) > 1:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(sys.argv[1], sys.argv[2])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
