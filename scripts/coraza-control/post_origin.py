from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def _ok(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n: self.rfile.read(n)
        body = b"<html><body>accepted</body></html>"
        self.send_response(200)
        self.send_header("Content-Type","text/html")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers(); self.wfile.write(body)
    do_GET = do_POST = _ok
ThreadingHTTPServer((sys.argv[1], 8098), H).serve_forever()
