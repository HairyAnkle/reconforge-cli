from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import threading

from reconforge.core import (
    _normalize_host,
    ensure_workspace,
    load_targets,
    run_ports,
    run_report,
    run_webdirs,
    write_lines,
)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", ""):
            body = b"<html><title>Local</title></html>"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path in ("/admin", "/login"):
            body = b"ok"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return


def _start_http_server() -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_target_intake_and_report(tmp_path: Path) -> None:
    list_file = tmp_path / "targets.txt"
    list_file.write_text("example.com\n10.0.0.1\n", encoding="utf-8")

    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("+api.example.com\n-example.com\n", encoding="utf-8")

    in_scope, out_scope = load_targets(domain="seed.example.com", list_path=list_file, scope_path=scope_file)
    assert "api.example.com" in in_scope
    assert "example.com" in out_scope
    assert "example.com" not in in_scope

    ensure_workspace(tmp_path)
    write_lines(tmp_path / "subdomains" / "resolved.txt", ["a.example.com", "b.example.com"])
    write_lines(tmp_path / "alive" / "alive.txt", ["https://a.example.com"])
    write_lines(tmp_path / "ports" / "services.txt", ["a.example.com:443\thttps"])
    write_lines(tmp_path / "web" / "endpoints.txt", ["https://a.example.com/admin"])
    (tmp_path / "ports" / "inventory.json").write_text('{"https": 1}', encoding="utf-8")

    report = run_report(tmp_path)
    content = report.read_text(encoding="utf-8")
    assert "Directory findings: **1**" in content
    assert "- https: **1**" in content


def test_normalize_host_variants() -> None:
    assert _normalize_host("https://localhost:8080/path") == "localhost"
    assert _normalize_host("http://example.com") == "example.com"
    assert _normalize_host("localhost:8443") == "localhost"
    assert _normalize_host("api.example.com/some/path") == "api.example.com"


def test_webdirs_wordlist(tmp_path: Path) -> None:
    server, thread = _start_http_server()
    host, port = server.server_address
    try:
        input_file = tmp_path / "alive.txt"
        input_file.write_text(f"http://{host}:{port}\n", encoding="utf-8")

        wordlist = tmp_path / "words.txt"
        wordlist.write_text("admin\nlogin\nmissing\n", encoding="utf-8")

        findings = run_webdirs(input_path=input_file, out_dir=tmp_path, wordlist_path=wordlist)
        urls = sorted(f.url for f in findings)
        assert f"http://{host}:{port}/admin" in urls
        assert f"http://{host}:{port}/login" in urls
        assert all("missing" not in u for u in urls)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_ports_inventory(tmp_path: Path) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    try:
        input_file = tmp_path / "alive.txt"
        input_file.write_text("http://127.0.0.1\n", encoding="utf-8")
        results = run_ports(input_file, tmp_path, top=1, full_scan=False, rate=1000, timeout=0.05)
        assert "127.0.0.1" in results
        inventory = (tmp_path / "ports" / "inventory.json").read_text(encoding="utf-8")
        assert isinstance(inventory, str)
    finally:
        sock.close()
