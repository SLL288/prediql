"""Out-of-band (OOB) interaction server — the near-zero-FP oracle for blind bugs.

Blind SSRF, blind command execution and other out-of-band injections produce no
evidence in the HTTP response. The proof is instead *interaction*: the target
makes an outbound request to a host we control, carrying a token only our payload
could have planted. This server is that collaborator — a tiny HTTP listener that
records every token it is hit with, so the oracle can confirm a finding by
checking :meth:`OOBServer.seen`.

Deliberately minimal and stdlib-only (no new dependency). HTTP is enough for the
GraphQL case (``http://<oob>/<token>`` reached by an SSRF fetch or a
``curl http://<oob>/<token>`` injected into a shell). DNS-only exfiltration would
need a DNS listener; out of scope here and noted as future work.
"""
from __future__ import annotations

import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class OOBServer:
    """Records inbound tokens. Reachable by the target under test.

    ``host`` is the address the *target* uses to reach us, which for a Dockerised
    target is typically ``host.docker.internal``; it is embedded in payloads and
    is not necessarily the bind address (always ``0.0.0.0``).
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._advertised_host = host
        self._seen: set[str] = set()
        self._lock = threading.Lock()
        server = self  # captured by the handler

        class _Handler(BaseHTTPRequestHandler):
            def _record(self) -> None:
                # Any path segment or query value is treated as a token.
                raw = self.path.lstrip("/")
                token = raw.split("?", 1)[0].split("/", 1)[0]
                if token:
                    server._mark(token)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = _record
            do_POST = _record
            do_PUT = _record

            def log_message(self, *args) -> None:  # silence the default stderr spam
                return

        self._httpd = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    # -- lifecycle --------------------------------------------------------
    def start(self) -> "OOBServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def __enter__(self) -> "OOBServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- addressing -------------------------------------------------------
    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://{self._advertised_host}:{self.port}"

    def new_token(self) -> str:
        return "pqloob" + secrets.token_hex(8)

    def url_for(self, token: str) -> str:
        return f"{self.base_url}/{token}"

    @property
    def host(self) -> str:
        """The host the target uses to reach us (not the bind address)."""
        return self._advertised_host

    def parts_for(self, token: str) -> dict[str, object]:
        """The callback as separate URL components, for a resolver that builds a
        URL from ``scheme``/``host``/``port``/``path`` arguments (e.g. DVGA's
        importPaste) rather than taking one URL string."""
        return {"scheme": "http", "host": self._advertised_host,
                "port": self.port, "path": f"/{token}"}

    # -- recording / query ------------------------------------------------
    def _mark(self, token: str) -> None:
        with self._lock:
            self._seen.add(token)

    def seen(self, token: str) -> bool:
        """True iff an inbound request carried ``token`` — the confirmation."""
        with self._lock:
            return token in self._seen
