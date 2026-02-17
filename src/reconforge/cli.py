from __future__ import annotations

import argparse
from pathlib import Path

from reconforge.core import run_alive, run_ports, run_report, run_subdomains


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reconforge", description="ReconForge CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    subdomains = sub.add_parser("subdomains", help="Collect and resolve built-in common subdomains")
    subdomains.add_argument("--domain", required=True)
    subdomains.add_argument("--out", required=True)

    alive = sub.add_parser("alive", help="Probe hosts for live HTTP/HTTPS endpoints")
    alive.add_argument("--input", required=True)
    alive.add_argument("--out", required=True)

    ports = sub.add_parser("ports", help="Scan a small top-port set")
    ports.add_argument("--input", required=True)
    ports.add_argument("--out", required=True)

    report = sub.add_parser("report", help="Generate Markdown/JSON summary")
    report.add_argument("--input", required=True)

    run = sub.add_parser("run", help="Run subdomains -> alive -> ports -> report")
    run.add_argument("--domain", required=True)
    run.add_argument("--out", required=True)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "subdomains":
        results = run_subdomains(domain=args.domain, out_dir=Path(args.out))
        print(f"resolved={len(results)}")
    elif args.command == "alive":
        results = run_alive(input_path=Path(args.input), out_dir=Path(args.out))
        print(f"alive={len(results)}")
    elif args.command == "ports":
        results = run_ports(input_path=Path(args.input), out_dir=Path(args.out))
        print(f"hosts_scanned={len(results)}")
    elif args.command == "report":
        report_path = run_report(out_dir=Path(args.input))
        print(f"report={report_path}")
    elif args.command == "run":
        out = Path(args.out)
        run_subdomains(domain=args.domain, out_dir=out)
        resolved = out / "subdomains" / "resolved.txt"
        run_alive(input_path=resolved, out_dir=out)
        alive_txt = out / "alive" / "alive.txt"
        run_ports(input_path=alive_txt, out_dir=out)
        report_path = run_report(out_dir=out)
        print(f"complete={report_path}")


if __name__ == "__main__":
    main()
