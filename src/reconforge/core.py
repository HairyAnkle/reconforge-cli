from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import socket
import urllib.request
from urllib.error import URLError, HTTPError

COMMON_SUBS = ["www", "api", "dev", "staging", "admin", "app", "portal"]
TOP_PORTS = [80, 443, 8080, 8443, 22, 21, 25, 53, 3306, 5432]


@dataclass
class ProbeResult:
    url: str
    status_code: int
    title: str


def ensure_workspace(out_dir: Path) -> None:
    for folder in ["scope", "subdomains", "alive", "ports", "web", "report", "logs"]:
        (out_dir / folder).mkdir(parents=True, exist_ok=True)


def write_lines(path: Path, values: list[str]) -> None:
    path.write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8")


def resolve_hosts(hosts: list[str]) -> tuple[list[str], list[str]]:
    resolved: list[str] = []
    failed: list[str] = []
    for host in sorted(set(hosts)):
        try:
            socket.gethostbyname(host)
            resolved.append(host)
        except socket.gaierror:
            failed.append(host)
    return resolved, failed


def run_subdomains(domain: str, out_dir: Path) -> list[str]:
    ensure_workspace(out_dir)
    candidates = [f"{sub}.{domain}" for sub in COMMON_SUBS] + [domain]
    all_path = out_dir / "subdomains" / "all.txt"
    write_lines(all_path, sorted(set(candidates)))

    resolved, failed = resolve_hosts(candidates)
    write_lines(out_dir / "subdomains" / "resolved.txt", resolved)
    write_lines(out_dir / "subdomains" / "failed.txt", failed)

    sources = {
        "strategy": "builtin_common_subdomains",
        "count_all": len(set(candidates)),
        "count_resolved": len(resolved),
    }
    (out_dir / "subdomains" / "sources.json").write_text(
        json.dumps(sources, indent=2), encoding="utf-8"
    )
    return resolved


def _extract_title(body: str) -> str:
    lower = body.lower()
    if "<title>" not in lower or "</title>" not in lower:
        return ""
    start = lower.index("<title>") + len("<title>")
    end = lower.index("</title>", start)
    return body[start:end].strip().replace("\n", " ")


def probe_host(host: str, timeout: float = 4.0) -> ProbeResult | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        req = urllib.request.Request(url, headers={"User-Agent": "reconforge/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(4096).decode("utf-8", errors="ignore")
                return ProbeResult(url=url, status_code=resp.getcode(), title=_extract_title(body))
        except (URLError, HTTPError, TimeoutError):
            continue
    return None


def run_alive(input_path: Path, out_dir: Path) -> list[ProbeResult]:
    ensure_workspace(out_dir)
    hosts = [line.strip() for line in input_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    results: list[ProbeResult] = []
    for host in hosts:
        hit = probe_host(host)
        if hit:
            results.append(hit)

    alive_hosts = [r.url for r in results]
    write_lines(out_dir / "alive" / "alive.txt", alive_hosts)
    write_lines(out_dir / "web" / "titles.txt", [f"{r.url}\t{r.title}" for r in results])
    (out_dir / "alive" / "alive.json").write_text(
        json.dumps([r.__dict__ for r in results], indent=2), encoding="utf-8"
    )
    return results


def scan_top_ports(host: str, timeout: float = 0.3) -> list[int]:
    open_ports: list[int] = []
    for port in TOP_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append(port)
            except OSError:
                continue
    return open_ports


def run_ports(input_path: Path, out_dir: Path) -> dict[str, list[int]]:
    ensure_workspace(out_dir)
    hosts = [line.strip() for line in input_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    cleaned_hosts = [h.split("://", 1)[-1].split("/", 1)[0] for h in hosts]

    results: dict[str, list[int]] = {}
    services_rows: list[str] = []
    for host in sorted(set(cleaned_hosts)):
        ports = scan_top_ports(host)
        results[host] = ports
        for port in ports:
            services_rows.append(f"{host}:{port}")

    write_lines(out_dir / "ports" / "services.txt", services_rows)
    (out_dir / "ports" / "ports.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


def run_report(out_dir: Path) -> Path:
    ensure_workspace(out_dir)
    subdomains = (out_dir / "subdomains" / "resolved.txt")
    alive = (out_dir / "alive" / "alive.txt")
    services = (out_dir / "ports" / "services.txt")

    sub_count = len(subdomains.read_text(encoding="utf-8").splitlines()) if subdomains.exists() else 0
    alive_count = len(alive.read_text(encoding="utf-8").splitlines()) if alive.exists() else 0
    svc_count = len(services.read_text(encoding="utf-8").splitlines()) if services.exists() else 0

    report_md = out_dir / "report" / "report.md"
    report_md.write_text(
        "\n".join(
            [
                "# ReconForge Report",
                "",
                "## Summary",
                f"- Resolved subdomains: **{sub_count}**",
                f"- Live web endpoints: **{alive_count}**",
                f"- Open service entries: **{svc_count}**",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    summary = {
        "resolved_subdomains": sub_count,
        "live_web_endpoints": alive_count,
        "open_service_entries": svc_count,
    }
    (out_dir / "report" / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return report_md
