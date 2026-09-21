import os
import socket
import time
import secrets
import threading

from http.server import (
    ThreadingHTTPServer,
    BaseHTTPRequestHandler
)


class ShareManager:

    def __init__(self):

        self.server = None
        self.thread = None
        self.file_path = None
        self.token = None
        self.expiry = 0
        self.port = 8765

    def get_local_ip(self):

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        try:

            sock.connect(
                ("8.8.8.8", 80)
            )

            return sock.getsockname()[0]

        except Exception:

            return "127.0.0.1"

        finally:

            sock.close()

    def start(
        self,
        file_path,
        duration_minutes
    ):

        self.stop()

        self.file_path = file_path

        self.token = secrets.token_urlsafe(
            24
        )

        self.expiry = (
            time.time() +
            duration_minutes * 60
        )

        manager = self

        class Handler(BaseHTTPRequestHandler):

            def log_message(
                self,
                format,
                *args
            ):
                return

            def do_GET(self):

                expected = (
                    "/download/" +
                    manager.token
                )

                if self.path != expected:

                    self.send_response(404)
                    self.end_headers()

                    self.wfile.write(
                        b"Invalid share link."
                    )

                    return

                if time.time() > manager.expiry:

                    self.send_response(410)
                    self.end_headers()

                    self.wfile.write(
                        b"Share link expired."
                    )

                    return

                if not os.path.isfile(
                    manager.file_path
                ):

                    self.send_response(404)
                    self.end_headers()

                    self.wfile.write(
                        b"File unavailable."
                    )

                    return

                try:

                    size = os.path.getsize(
                        manager.file_path
                    )

                    filename = os.path.basename(
                        manager.file_path
                    )

                    self.send_response(200)

                    self.send_header(
                        "Content-Type",
                        "application/octet-stream"
                    )

                    self.send_header(
                        "Content-Length",
                        str(size)
                    )

                    self.send_header(
                        "Content-Disposition",
                        f'attachment; filename="{filename}"'
                    )

                    self.end_headers()

                    with open(
                        manager.file_path,
                        "rb"
                    ) as file:

                        while True:

                            chunk = file.read(
                                1024 * 1024
                            )

                            if not chunk:
                                break

                            self.wfile.write(
                                chunk
                            )

                except Exception:
                    pass

        try:

            self.server = ThreadingHTTPServer(
                ("0.0.0.0", self.port),
                Handler
            )

        except OSError:

            raise RuntimeError(
                f"Port {self.port} is already in use."
            )

        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True
        )

        self.thread.start()

        ip = self.get_local_ip()

        return (
            f"http://{ip}:{self.port}"
            f"/download/{self.token}"
        )

    def stop(self):

        if self.server:

            try:
                self.server.shutdown()
            except Exception:
                pass

            try:
                self.server.server_close()
            except Exception:
                pass

        self.server = None
        self.thread = None
        self.file_path = None
        self.token = None
        self.expiry = 0

    def active(self):

        return (
            self.server is not None
            and time.time() < self.expiry
        )