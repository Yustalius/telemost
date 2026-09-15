#!/usr/bin/env python3

import argparse
import http.client
import http.server
import ssl
import time
from urllib.parse import urlsplit


HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class BufferedFront(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "diagnostic-buffer-front"
    sys_version = ""

    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def log_message(self, _format, *_args):
        return

    def forward(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length > 256 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(content_length)
        headers = {
            name: value
            for name, value in self.headers.items()
            if name.lower() not in HOP_HEADERS and name.lower() != "host"
        }
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        backend = http.client.HTTPSConnection(
            self.server.backend_host,
            self.server.backend_port,
            timeout=30,
            context=context,
        )
        try:
            backend.request(self.command, self.path, body=body, headers=headers)
            response = backend.getresponse()
            response_body = response.read()
        except (OSError, http.client.HTTPException):
            self.send_error(502)
            return
        finally:
            backend.close()
        time.sleep(self.server.delay_ms / 1000)
        self.send_response(response.status)
        for name, value in response.getheaders():
            if name.lower() not in HOP_HEADERS and name.lower() != "content-length":
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)
        self.wfile.flush()


class ThreadingServer(http.server.ThreadingHTTPServer):
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True)
    parser.add_argument("--backend", required=True)
    parser.add_argument("--delay-ms", required=True, type=int)
    args = parser.parse_args()
    listen_host, listen_port = args.listen.rsplit(":", 1)
    backend = urlsplit(args.backend)
    if backend.scheme != "https" or not backend.hostname:
        parser.error("--backend must be an https URL")
    server = ThreadingServer((listen_host, int(listen_port)), BufferedFront)
    server.backend_host = backend.hostname
    server.backend_port = backend.port or 443
    server.delay_ms = args.delay_ms
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
