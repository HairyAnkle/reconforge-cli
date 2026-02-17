from __future__ import annotations

from dataclasses import asdict, dataclass
from ipaddress import ip_network
from pathlib import Path
import json
import socket
import time
import urllib.request
from urllib.error import URLError, HTTPError
from urllib.parse import quote, urljoin, urlparse

COMMON_SUBS = ["www", "api", "dev", "staging", "admin", "app", "portal"]
COMMON_PORTS = [80, 443, 8080, 8443, 22, 21, 25, 53, 3306, 5432]
SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    443: "https",
    3306: "mysql",
    5432: "postgresql",
    8080: "http-alt",
    8443: "https-alt",
}


@dataclass
class ProbeResult:
    url: str
    status_code: int
    title: str


@dataclass
class DirResult:
    base_url: str
    path: str
    url: str
    status_code: int
    length: int


def ensure_workspace(out_dir: Path) -> None:
    for folder in ["scope", "subdomains", "alive", "ports", "web", "report", "logs"]:
        (out_dir / folder).mkdir(parents=True, exist_ok=True)


def write_lines(path: Path, values: list[str]) -> None:
    path.write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8")


def load_targets(
    domain: str | None = None,
    cidr: str | None = None,
    list_path: Path | None = None,
    scope_path: Path | None = None,
) -> tuple[list[str], list[str]]:
    in_scope: set[str] = set()
    out_scope: set[str] = set()

    if domain:
        in_scope.add(domain.strip())

    if cidr:
        net = ip_network(cidr.strip(), strict=False)
        for ip in net.hosts():
            in_scope.add(str(ip))

    if list_path and list_path.exists():
        for line in list_path.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if value and not value.startswith("#"):
                in_scope.add(value)

    if scope_path and scope_path.exists():
        for raw in scope_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("+"):
                in_scope.add(line[1:].strip())
            elif line.startswith("-"):
                out_scope.add(line[1:].strip())
            else:
                in_scope.add(line)

    final_in_scope = sorted(v for v in in_scope if v and v not in out_scope)
    return final_in_scope, sorted(out_scope)


def write_scope_files(out_dir: Path, in_scope: list[str], out_scope: list[str]) -> None:
    ensure_workspace(out_dir)
    write_lines(out_dir / "scope" / "in_scope.txt", in_scope)
    write_lines(out_dir / "scope" / "out_of_scope.txt", out_scope)


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


def _source_common(domain: str, _: Path | None = None) -> list[str]:
    return [f"{sub}.{domain}" for sub in COMMON_SUBS] + [domain]


def _source_wordlist(domain: str, wordlist_path: Path | None = None) -> list[str]:
    if not wordlist_path or not wordlist_path.exists():
        return []
    words = [w.strip() for w in wordlist_path.read_text(encoding="utf-8").splitlines() if w.strip()]
    return [f"{w}.{domain}" for w in words]


def run_subdomains(
    domain: str,
    out_dir: Path,
    sources: list[str] | None = None,
    wordlist_path: Path | None = None,
) -> list[str]:
    ensure_workspace(out_dir)
    requested = sources or ["common"]

    source_impl = {
        "common": _source_common,
        "wordlist": _source_wordlist,
    }

    all_candidates: list[str] = []
    used_sources: list[str] = []
    for source in requested:
        fn = source_impl.get(source.strip())
        if not fn:
            continue
        used_sources.append(source)
        all_candidates.extend(fn(domain, wordlist_path))

    all_candidates = sorted(set(all_candidates))
    write_lines(out_dir / "subdomains" / "all.txt", all_candidates)

    resolved, failed = resolve_hosts(all_candidates)
    write_lines(out_dir / "subdomains" / "resolved.txt", resolved)
    write_lines(out_dir / "subdomains" / "failed.txt", failed)

    sources_payload = {
        "enabled": used_sources,
        "count_all": len(all_candidates),
        "count_resolved": len(resolved),
    }
    (out_dir / "subdomains" / "sources.json").write_text(json.dumps(sources_payload, indent=2), encoding="utf-8")
    return resolved


def _extract_title(body: str) -> str:
    lower = body.lower()
    if "<title>" not in lower or "</title>" not in lower:
        return ""
    start = lower.index("<title>") + len("<title>")
    end = lower.index("</title>", start)
    return body[start:end].strip().replace("\n", " ")


def _normalize_host(value: str) -> str:
    if "://" in value:
        parsed = urlparse(value)
        if parsed.hostname:
            return parsed.hostname
    host = value.split("/", 1)[0]
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host


def _normalize_base_url(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        return ""
    if "://" not in stripped:
        stripped = f"http://{stripped}"
    parsed = urlparse(stripped)
    if not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


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

    write_lines(out_dir / "alive" / "alive.txt", [r.url for r in results])
    write_lines(out_dir / "web" / "titles.txt", [f"{r.url}\t{r.title}" for r in results])
    (out_dir / "alive" / "alive.json").write_text(json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")
    return results


def _scan_ports(host: str, ports: list[int], timeout: float, rate: float) -> list[int]:
    open_ports: list[int] = []
    delay = 1.0 / rate if rate > 0 else 0.0
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append(port)
            except OSError:
                continue
        if delay:
            time.sleep(delay)
    return open_ports


def run_ports(
    input_path: Path,
    out_dir: Path,
    *,
    top: int = 10,
    full_scan: bool = False,
    rate: float = 200.0,
    timeout: float = 0.3,
) -> dict[str, list[int]]:
    ensure_workspace(out_dir)
    hosts = [line.strip() for line in input_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    cleaned_hosts = [_normalize_host(h) for h in hosts]
    cleaned_hosts = [h for h in cleaned_hosts if h]

    if full_scan:
        target_ports = list(range(1, 65536))
    else:
        target_ports = COMMON_PORTS[: max(1, min(top, len(COMMON_PORTS)))]

    results: dict[str, list[int]] = {}
    services_rows: list[str] = []
    inventory: dict[str, int] = {}

    for host in sorted(set(cleaned_hosts)):
        ports = _scan_ports(host, target_ports, timeout=timeout, rate=rate)
        results[host] = ports
        for port in ports:
            service = SERVICE_MAP.get(port, "unknown")
            services_rows.append(f"{host}:{port}\t{service}")
            inventory[service] = inventory.get(service, 0) + 1

    write_lines(out_dir / "ports" / "services.txt", services_rows)
    (out_dir / "ports" / "ports.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (out_dir / "ports" / "inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    return results


def run_webdirs(input_path: Path, out_dir: Path, wordlist_path: Path, timeout: float = 3.0) -> list[DirResult]:
    ensure_workspace(out_dir)
    targets_raw = [line.strip() for line in input_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    words = [line.strip().lstrip("/") for line in wordlist_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    targets = sorted(set(_normalize_base_url(t) for t in targets_raw))
    targets = [t for t in targets if t]

    findings: list[DirResult] = []
    endpoint_rows: list[str] = []

    for base in targets:
        base_slash = base.rstrip("/") + "/"
        for word in words:
            candidate = urljoin(base_slash, quote(word))
            req = urllib.request.Request(candidate, headers={"User-Agent": "reconforge/0.1"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    body = resp.read(2048)
                    status = resp.getcode()
                    if status < 400:
                        row = DirResult(base_url=base, path=f"/{word}", url=candidate, status_code=status, length=len(body))
                        findings.append(row)
                        endpoint_rows.append(candidate)
            except HTTPError as exc:
                if exc.code in (401, 403):
                    row = DirResult(base_url=base, path=f"/{word}", url=candidate, status_code=exc.code, length=0)
                    findings.append(row)
                    endpoint_rows.append(candidate)
                continue
            except (URLError, TimeoutError):
                continue

    write_lines(out_dir / "web" / "endpoints.txt", sorted(set(endpoint_rows)))
    (out_dir / "web" / "directories.json").write_text(json.dumps([asdict(f) for f in findings], indent=2), encoding="utf-8")
    return findings


def run_report(out_dir: Path) -> Path:
    ensure_workspace(out_dir)
    subdomains = out_dir / "subdomains" / "resolved.txt"
    alive = out_dir / "alive" / "alive.txt"
    services = out_dir / "ports" / "services.txt"
    endpoints = out_dir / "web" / "endpoints.txt"
    inventory_path = out_dir / "ports" / "inventory.json"

    sub_count = len(subdomains.read_text(encoding="utf-8").splitlines()) if subdomains.exists() else 0
    alive_count = len(alive.read_text(encoding="utf-8").splitlines()) if alive.exists() else 0
    svc_count = len(services.read_text(encoding="utf-8").splitlines()) if services.exists() else 0
    endpoint_count = len(endpoints.read_text(encoding="utf-8").splitlines()) if endpoints.exists() else 0
    inventory = json.loads(inventory_path.read_text(encoding="utf-8")) if inventory_path.exists() else {}

    inv_rows = [f"- {name}: **{count}**" for name, count in sorted(inventory.items())]
    report_lines = [
        "# ReconForge Report",
        "",
        "## Summary",
        f"- Resolved subdomains: **{sub_count}**",
        f"- Live web endpoints: **{alive_count}**",
        f"- Open service entries: **{svc_count}**",
        f"- Directory findings: **{endpoint_count}**",
        "",
        "## Service inventory",
        *(inv_rows or ["- none"]),
    ]

    report_md = out_dir / "report" / "report.md"
    report_md.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    summary = {
        "resolved_subdomains": sub_count,
        "live_web_endpoints": alive_count,
        "open_service_entries": svc_count,
        "directory_findings": endpoint_count,
        "service_inventory": inventory,
    }
    (out_dir / "report" / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return report_md
