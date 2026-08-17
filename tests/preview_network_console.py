"""Loopback-only browser QA with synthetic accounts and real in-process services.

This intentionally authenticates the test owner in TestClient. It does NOT test
browser passkeys, TLS, deployment, or production login. Never package this helper.
Run: python tests/preview_network_console.py --synthetic-preview
"""

from __future__ import annotations

import argparse
import tempfile
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from test_network_accounts import NOW, network_setup

from controlforge.standalone.store import StandaloneStore, _utc_text


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--synthetic-preview", action="store_true", required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--device-scenarios", action="store_true")
    parser.add_argument("--fail-device-details", action="store_true")
    parser.add_argument("--finding-scenarios", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="controlforge-ui-qa-") as directory:
        fixture = network_setup.__wrapped__(Path(directory))
        client = fixture[-1]
        if args.finding_scenarios:
            from test_finding_guidance import seed_findings

            seed_findings(fixture[0], str(fixture[5]["tenant_id"]), "Reception Mac <synthetic>")
            seed_findings(fixture[0], str(fixture[6]["tenant_id"]), "Beta private Mac")
        if args.device_scenarios:
            database, alpha = fixture[0], fixture[5]
            store = StandaloneStore(database)
            tenant_id = str(alpha["tenant_id"])
            for device_id, name, status, age, credential in [
                ("qa-fresh", "Reception Mac", "active", 30, True),
                ("qa-stale", "Finance Mac", "active", 1800, True),
                ("qa-new", "New starter's Mac", "active", None, True),
                ("qa-expired", "Expired credential Mac", "active", 30, False),
                ("qa-revoked", "Retired Mac", "revoked", 86400, False),
                ("qa-enrolling", "Setup interrupted Mac", "enrolling", None, False),
                ("qa-future", "Clock mismatch Mac", "active", -120, True),
            ]:
                store.register_device(tenant_id, device_id, name, "macos", NOW)
                with database.connect() as connection:
                    connection.execute(
                        "UPDATE devices SET status = ?, last_seen_at = ? "
                        "WHERE tenant_id = ? AND device_id = ?",
                        (
                            status,
                            _utc_text(NOW - timedelta(seconds=age)) if age is not None else None,
                            tenant_id,
                            device_id,
                        ),
                    )
                if credential:
                    store.register_device_credential(
                        "synthetic-" + device_id,
                        tenant_id,
                        device_id,
                        "Synthetic preview only",
                        "not-a-real-ciphertext",
                        "not-a-real-iv",
                        NOW,
                        NOW + timedelta(days=30),
                    )

        class PreviewHandler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                self.forward()

            def do_POST(self) -> None:
                self.forward()

            def forward(self) -> None:
                target = urlsplit(self.path)
                if target.scheme or target.netloc or not target.path.startswith("/"):
                    self.send_error(400)
                    return
                if args.fail_device_details and target.path.startswith("/v1/dashboard/devices/"):
                    self.send_error(503, "Synthetic device-detail outage")
                    return
                length = int(self.headers.get("content-length", "0"))
                if length < 0 or length > 65536:
                    self.send_error(413)
                    return
                forwarded = {
                    key: self.headers[key]
                    for key in ("x-network-id", "x-csrf-token")
                    if key in self.headers
                }
                result = client.request(
                    self.command, self.path, headers=forwarded, content=self.rfile.read(length)
                )
                self.send_response(result.status_code)
                for key in ("content-type", "content-security-policy", "cache-control", "location"):
                    if key in result.headers:
                        self.send_header(key, result.headers[key])
                self.send_header(
                    "X-ControlForge-Test-Preview", "synthetic-owner-no-browser-auth-proof"
                )
                self.end_headers()
                self.wfile.write(result.content)

        server = HTTPServer(("127.0.0.1", args.port), PreviewHandler)
        print(f"Synthetic account preview on http://127.0.0.1:{args.port}/console", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
            client.close()


if __name__ == "__main__":
    main()
