from __future__ import annotations

import argparse
from pathlib import Path

from reconforge.core import (
    load_targets,
    run_alive,
    run_ports,
    run_report,
    run_subdomains,
    run_webdirs,
    write_lines,
    write_scope_files,
)


def _add_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--domain")
    parser.add_argument("--cidr")
    parser.add_argument("--list", dest="list_path")
    parser.add_argument("--scope")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reconforge", description="ReconForge CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    targets = sub.add_parser("targets", help="Build in-scope/out-of-scope files from domain/cidr/list/scope")
    _add_target_args(targets)
    targets.add_argument("--out", required=True)

    subdomains = sub.add_parser("subdomains", help="Collect and resolve subdomains")
    subdomains.add_argument("--domain", required=True)
    subdomains.add_argument("--sources", default="common", help="Comma-separated: common,wordlist")
    subdomains.add_argument("--wordlist", help="Optional wordlist for wordlist source")
    subdomains.add_argument("--out", required=True)

    alive = sub.add_parser("alive", help="Probe hosts for live HTTP/HTTPS endpoints")
    alive.add_argument("--input", required=True)
    alive.add_argument("--out", required=True)

    ports = sub.add_parser("ports", help="Scan top or full ports")
    ports.add_argument("--input", required=True)
    ports.add_argument("--out", required=True)
    ports.add_argument("--top", type=int, default=10)
    ports.add_argument("--full", action="store_true")
    ports.add_argument("--rate", type=float, default=200.0)
    ports.add_argument("--timeout", type=float, default=0.3)

    webdirs = sub.add_parser("webdirs", help="Discover common web directories using a wordlist")
    webdirs.add_argument("--input", required=True, help="Path to alive URLs or host list")
    webdirs.add_argument("--wordlist", required=True, help="Wordlist file (one path per line)")
    webdirs.add_argument("--out", required=True)

    report = sub.add_parser("report", help="Generate Markdown/JSON summary")
    report.add_argument("--input", required=True)

    run = sub.add_parser("run", help="Run full pipeline")
    _add_target_args(run)
    run.add_argument("--sources", default="common", help="Comma-separated: common,wordlist")
    run.add_argument("--sub-wordlist", help="Subdomain wordlist (for wordlist source)")
    run.add_argument("--web-wordlist", help="Optional webdirs wordlist")
    run.add_argument("--top", type=int, default=10)
    run.add_argument("--full", action="store_true")
    run.add_argument("--rate", type=float, default=200.0)
    run.add_argument("--timeout", type=float, default=0.3)
    run.add_argument("--out", required=True)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "targets":
        in_scope, out_scope = load_targets(
            domain=args.domain,
            cidr=args.cidr,
            list_path=Path(args.list_path) if args.list_path else None,
            scope_path=Path(args.scope) if args.scope else None,
        )
        write_scope_files(Path(args.out), in_scope, out_scope)
        print(f"in_scope={len(in_scope)}")
        print(f"out_scope={len(out_scope)}")
        for item in in_scope:
            print(item)

    elif args.command == "subdomains":
        results = run_subdomains(
            domain=args.domain,
            out_dir=Path(args.out),
            sources=[s.strip() for s in args.sources.split(",") if s.strip()],
            wordlist_path=Path(args.wordlist) if args.wordlist else None,
        )
        print(f"resolved={len(results)}")
        for host in results:
            print(host)

    elif args.command == "alive":
        results = run_alive(input_path=Path(args.input), out_dir=Path(args.out))
        print(f"alive={len(results)}")
        for row in results:
            print(f"{row.status_code}\t{row.url}\t{row.title}")

    elif args.command == "ports":
        results = run_ports(
            input_path=Path(args.input),
            out_dir=Path(args.out),
            top=args.top,
            full_scan=args.full,
            rate=args.rate,
            timeout=args.timeout,
        )
        print(f"hosts_scanned={len(results)}")
        for host, ports in sorted(results.items()):
            port_text = ",".join(str(p) for p in ports) if ports else "none"
            print(f"{host}\t{port_text}")

    elif args.command == "webdirs":
        findings = run_webdirs(input_path=Path(args.input), out_dir=Path(args.out), wordlist_path=Path(args.wordlist))
        print(f"directories={len(findings)}")
        for row in findings:
            print(f"{row.status_code}\t{row.url}\tlen={row.length}")

    elif args.command == "report":
        report_path = run_report(out_dir=Path(args.input))
        print(f"report={report_path}")
        print(report_path.read_text(encoding="utf-8"))

    elif args.command == "run":
        out = Path(args.out)
        in_scope, out_scope = load_targets(
            domain=args.domain,
            cidr=args.cidr,
            list_path=Path(args.list_path) if args.list_path else None,
            scope_path=Path(args.scope) if args.scope else None,
        )
        write_scope_files(out, in_scope, out_scope)
        print(f"in_scope={len(in_scope)}")

        domain_for_sub = args.domain
        if not domain_for_sub:
            domain_for_sub = next((v for v in in_scope if "." in v and not v.replace(".", "").isdigit()), "")
        if not domain_for_sub:
            raise SystemExit("run requires --domain (or domain present in scope/list for subdomains step)")

        resolved = run_subdomains(
            domain=domain_for_sub,
            out_dir=out,
            sources=[s.strip() for s in args.sources.split(",") if s.strip()],
            wordlist_path=Path(args.sub_wordlist) if args.sub_wordlist else None,
        )
        print(f"resolved={len(resolved)}")

        alive_input = out / "subdomains" / "resolved.txt"
        if not alive_input.exists() or not alive_input.read_text(encoding="utf-8").strip():
            # fallback to in-scope hosts/IPs
            fallback = out / "scope" / "in_scope.txt"
            write_lines(fallback, in_scope)
            alive_input = fallback

        alive = run_alive(input_path=alive_input, out_dir=out)
        print(f"alive={len(alive)}")

        ports = run_ports(
            input_path=out / "alive" / "alive.txt",
            out_dir=out,
            top=args.top,
            full_scan=args.full,
            rate=args.rate,
            timeout=args.timeout,
        )
        print(f"hosts_scanned={len(ports)}")

        if args.web_wordlist:
            findings = run_webdirs(
                input_path=out / "alive" / "alive.txt",
                out_dir=out,
                wordlist_path=Path(args.web_wordlist),
            )
            print(f"directories={len(findings)}")

        report_path = run_report(out_dir=out)
        print(f"complete={report_path}")
        print(report_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
