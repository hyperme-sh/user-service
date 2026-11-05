"""Disposable native-test SMTP receiver; no production credentials or delivery."""
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from socketserver import StreamRequestHandler, ThreadingTCPServer
import threading

messages = []
lock = threading.Lock()


class SMTP(StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 reset-test ESMTP\r\n")
        recipients = []
        while line := self.rfile.readline(65536):
            verb = line.split(b" ", 1)[0].strip().upper()
            if verb in {b"EHLO", b"HELO"}:
                self.wfile.write(b"250 reset-test\r\n")
            elif verb == b"MAIL":
                recipients = []
                self.wfile.write(b"250 OK\r\n")
            elif verb == b"RCPT":
                recipients.append(line.decode().split("<", 1)[1].split(">", 1)[0])
                self.wfile.write(b"250 OK\r\n")
            elif verb == b"DATA":
                self.wfile.write(b"354 Send data\r\n")
                data = bytearray()
                while (part := self.rfile.readline(65536)) not in {b".\r\n", b""}:
                    data.extend(part[1:] if part.startswith(b"..") else part)
                    if len(data) > 1024 * 1024:
                        return
                mail = BytesParser(policy=policy.default).parsebytes(bytes(data))
                body = mail.get_body(preferencelist=("plain",)) if mail.is_multipart() else mail
                with lock:
                    messages.append({"recipients": recipients, "text": body.get_content()})
                self.wfile.write(b"250 Accepted\r\n")
            elif verb == b"QUIT":
                self.wfile.write(b"221 Bye\r\n")
                return
            elif verb in {b"RSET", b"NOOP"}:
                self.wfile.write(b"250 OK\r\n")
            else:
                self.wfile.write(b"502 Unsupported\r\n")


class Capture(BaseHTTPRequestHandler):
    def do_GET(self):
        with lock:
            raw = json.dumps(messages).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    smtp = ThreadingTCPServer(("0.0.0.0", 2525), SMTP)
    threading.Thread(target=smtp.serve_forever, daemon=True).start()
    print("SMTP capture ready", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8025), Capture).serve_forever()
