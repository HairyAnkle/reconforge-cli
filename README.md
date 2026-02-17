# ReconForge CLI — Modular Pentest Recon Pipeline

A **CLI-based reconnaissance toolkit** designed for **authorized security testing**.  
ReconForge turns a target domain (or scope file) into a clean recon workspace: **subdomains → live hosts → ports → fingerprinting → optional screenshots/endpoints → report**.

> ⚠️ **Authorized use only.** Run this tool only on systems you own or where you have explicit written permission.

---

## Why this exists

Pentesting recon often becomes messy: outputs spread across tools, inconsistent formats, and hard-to-repeat workflows.  
ReconForge focuses on:

- **Repeatable** recon runs (consistent folder structure)
- **Modular** steps (run everything or just what you need)
- **Pentest-friendly outputs** (TXT + JSON + CSV)
- **Report-ready summaries** (Markdown report + JSON summary)

---

## Features (Planned / In Progress)

### Core
- ✅ Target intake: domain, CIDR, list file, scope file
- ✅ Subdomain collection (pluggable sources/modules)
- ✅ DNS resolve + dedup
- ✅ Live host probing (HTTP/HTTPS) + titles/status codes
- ✅ Port scanning (top ports / full scan, rate-limited)
- ✅ Service parsing + inventory summary
- ✅ Markdown report generation

### Optional modules
- ⏳ Tech fingerprint hints (headers, simple signatures)
- ⏳ Endpoint discovery (crawl + URL extraction)
- ⏳ Screenshots (integrate with `gowitness` / `aquatone` if installed)
- ⏳ Caching (avoid re-pulling passive sources)
- ⏳ Resume support (continue from partial runs)

> Roadmap is tracked in **Issues** and **Milestones**.

---

## Quick Start (Planned)

### Install (editable/dev)
```bash
git clone https://github.com/<your-username>/reconforge-cli.git
cd reconforge-cli
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Run full recon
```bash
reconforge run --domain example.com --out runs/example.com
```

### Run only parts
```bash
reconforge subdomains --domain example.com --out runs/example.com
reconforge alive --input runs/example.com/subdomains/resolved.txt --out runs/example.com
reconforge ports --input runs/example.com/alive/alive.txt --top 1000 --rate 200 --out runs/example.com
reconforge report --input runs/example.com --format md
```

---

## CLI Commands (Design)

### `run` (pipeline)
Runs selected modules in order.

```bash
reconforge run --domain example.com --out runs/example.com --modules subdomains,alive,ports,report
```

### `subdomains`
Collect + merge subdomains from enabled sources.

```bash
reconforge subdomains --domain example.com --out runs/example.com
```

### `alive`
Probe HTTP/HTTPS to identify live web hosts.

```bash
reconforge alive --input subdomains.txt --out runs/example.com --threads 50 --timeout 5
```

### `ports`
Scan ports (top ports by default). Full scans are opt-in and rate-limited.

```bash
reconforge ports --input runs/example.com/alive/alive.txt --top 1000 --rate 200 --out runs/example.com
```

### `report`
Generate a Markdown recon report.

```bash
reconforge report --input runs/example.com --format md
```

---

## Output Structure

Each run creates a predictable recon workspace:

```
runs/example.com/
├── scope/
│   ├── in_scope.txt
│   └── out_of_scope.txt
├── subdomains/
│   ├── all.txt
│   ├── sources.json
│   ├── resolved.txt
│   └── failed.txt
├── alive/
│   ├── alive.txt
│   ├── alive.json
│   └── tech.csv
├── ports/
│   ├── ports.json
│   ├── services.txt
│   └── nmap/
│       ├── scan.xml
│       ├── scan.gnmap
│       └── scan.nmap
├── web/
│   ├── titles.txt
│   ├── endpoints.txt
│   ├── params.txt
│   └── screenshots/   # optional
├── report/
│   ├── report.md
│   └── summary.json
└── logs/
    └── recon.log
```

---

## Configuration

ReconForge supports config via:
- CLI flags (highest priority)
- `reconforge.toml` (recommended)
- Environment variables (API keys for passive sources)

Example `reconforge.toml` (planned):

```toml
[general]
threads = 50
timeout = 5
rate = 200

[subdomains]
sources = ["crtsh", "passive_dns", "wordlist"]  # modules you enable
wordlist = "wordlists/subs.txt"

[ports]
top = 1000
full_scan = false
```

---

## Dependencies (Planned)

Python libraries:
- `typer` (CLI)
- `rich` (pretty terminal output)
- `httpx` (fast probing)
- `dnspython` (DNS)
- `pydantic` (structured results)
- `jinja2` (report templates)

Optional external tools (auto-detected):
- `nmap` (recommended for port scan output)
- `gowitness` or `aquatone` (screenshots)

---

## Security & Ethics

This tool is built for **professional recon workflows** and **authorized testing**.

✅ OK:
- scanning your own assets
- scanning assets with explicit permission (contract/scope)
- lab environments and CTF targets

❌ Not OK:
- scanning random public targets “for practice”
- stealthy abuse or evasion guidance
- any activity without consent

---

## Contributing

PRs welcome (especially for):
- new passive subdomain source modules
- improved parsers for port scan output
- better report templates
- unit tests + CI

---

## Credits

Inspired by real-world recon toolchains and the need for **repeatable outputs** in pentest engagements.
