# ReconForge CLI — Modular Pentest Recon Pipeline

A CLI-based reconnaissance toolkit for **authorized security testing**.

> ⚠️ Authorized use only. Run this tool only on systems you own or where you have explicit written permission.

## What is implemented now

### Core
- ✅ Target intake: domain / CIDR / list file / scope file (`targets`, `run`)
- ✅ Subdomain collection with pluggable sources (`common`, `wordlist`)
- ✅ DNS resolve + dedup
- ✅ Live host probing (HTTP/HTTPS) + titles/status
- ✅ Port scanning (top or full) + simple rate control
- ✅ Service parsing + inventory summary (`ports/inventory.json`)
- ✅ Markdown + JSON report generation

### Optional
- ✅ Endpoint directory discovery with wordlist (`webdirs`)
- ⏳ Tech fingerprint hints
- ⏳ Endpoint crawl + URL extraction
- ⏳ Screenshots integration (`gowitness`/`aquatone`)
- ⏳ Caching
- ⏳ Resume support

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e . --no-build-isolation
python3 -m reconforge --help
```

## Commands

- `targets` build `scope/in_scope.txt` and `scope/out_of_scope.txt`
- `subdomains` collect/resolve subdomains
- `alive` probe HTTP/HTTPS and print terminal output
- `ports` scan top/full ports and output inventory
- `webdirs` brute-force directories from a wordlist
- `report` generate and print Markdown report
- `run` full pipeline

## Examples

### 1) Build scope inputs

```bash
python3 -m reconforge targets --domain example.com --cidr 10.10.10.0/30 --list targets.txt --scope scope.txt --out runs/example
```

`scope.txt` format supports:
- `+value` include
- `-value` exclude
- `value` include

### 2) Subdomains with pluggable sources

```bash
python3 -m reconforge subdomains \
  --domain example.com \
  --sources common,wordlist \
  --wordlist wordlists/subs.txt \
  --out runs/example
```

### 3) Alive + ports + webdirs

```bash
python3 -m reconforge alive --input runs/example/subdomains/resolved.txt --out runs/example
python3 -m reconforge ports --input runs/example/alive/alive.txt --out runs/example --top 10 --rate 200
python3 -m reconforge webdirs --input runs/example/alive/alive.txt --wordlist wordlists/common.txt --out runs/example
python3 -m reconforge report --input runs/example
```

### 4) One-shot run

```bash
python3 -m reconforge run \
  --domain example.com \
  --sources common,wordlist \
  --sub-wordlist wordlists/subs.txt \
  --web-wordlist wordlists/common.txt \
  --top 10 --rate 200 \
  --out runs/example
```

## Output files

- `scope/in_scope.txt`, `scope/out_of_scope.txt`
- `subdomains/all.txt`, `resolved.txt`, `failed.txt`, `sources.json`
- `alive/alive.txt`, `alive/alive.json`, `web/titles.txt`
- `ports/services.txt`, `ports/ports.json`, `ports/inventory.json`
- `web/endpoints.txt`, `web/directories.json`
- `report/report.md`, `report/summary.json`
