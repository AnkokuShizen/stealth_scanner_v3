<div align="center">

# 🥷 Stealth Asset Scanner — v3.0

**Fast, quiet, complete discovery of internal web services — SYN-sweep millions of IPs per hour, then fingerprint every open web port with a real browser TLS handshake.**

[![Python](https://img.shields.io/badge/python-3.8%2B%20(stdlib%20only)-3776AB?logo=python&logoColor=white)](#-installation--build)
[![Go](https://img.shields.io/badge/prober-Go%201.22%2B-00ADD8?logo=go&logoColor=white)](#-installation--build)
[![Engine](https://img.shields.io/badge/L4-masscan%20%2F%20naabu-CB2B24)](#%EF%B8%8F-architecture)
[![Stealth](https://img.shields.io/badge/L7-uTLS%20browser%20fingerprint-8B9DC3)](#-stealth-layers)
[![Platform](https://img.shields.io/badge/platform-Linux-black?logo=linux&logoColor=white)](#-installation--build)

**📖 زبان فارسی / [Persian version](README.fa.md)**

</div>

---

## ⚠️ Legal Disclaimer

> [!WARNING]
> Use this tool **only on networks you are officially authorized to scan**. Unauthorized scanning is a crime in most jurisdictions.
> Sensitive ranges (OT/ICS, medical equipment, iLO/BMC server controllers) should always be excluded via `--exclude`.

## ⚙️ Architecture

A two-phase pipeline, each phase using the best tool for the job:

```
┌──────────────────────────┐      ┌────────────────────────────────┐
│  Phase 1 — L4 Discovery  │      │  Phase 2 — L7 Fingerprinting   │
│  Masscan / naabu (SYN)   │ ───► │  Go Prober v3 (uTLS browser)   │
│  millions of IPs / hour  │      │  favicon hash + tech + report  │
└──────────────────────────┘      └────────────────────────────────┘
```

- **Phase 1** finds open web ports across very large ranges using SYN scan (no full handshake — fast and quiet).
- **Phase 2** probes every open port with HTTP requests carrying a **real Chrome/Firefox/Edge TLS fingerprint** (uTLS), extracting titles, technologies, favicon hashes (mmh3/Shodan format), internal-IP leaks, and more.

## ✨ Highlights

- 🗺️ **Internet-scale Phase 1** — masscan with tuned rate/wait/retries, or naabu as an alternative engine
- 🥸 **Browser-grade Phase 2** — uTLS fingerprints, exact browser header order, stable per-IP user agents, jitter + think-time
- 🧠 **Adaptive throttling** — a circuit breaker halves the request rate when error rates suggest WAF throttling, then ramps back up
- 🏷️ **Appliance identification** — favicon mmh3 hashes matched against a custom database (FortiGate, vCenter, …)
- 📊 **Interactive HTML report** — single self-contained file with sortable tables
- 📈 **Asset drift tracking** — `--diff` reports new / removed / changed assets vs. the previous scan
- ⏯️ **Resume** — interrupted a huge scan? `--resume` picks up where it stopped
- 🧩 **Distributed sharding** — `--shard 2/4` across multiple servers (both masscan and prober honor it)
- 📣 **Telegram notifications** — summary pushed to your chat when the scan finishes
- 🧪 **Dry-run** — `--dry-run` prints the execution plan without sending a single packet

## 📋 Requirements

| Component | Required? | Notes |
|---|:---:|---|
| **Linux** | ✅ | SYN scanning needs raw sockets |
| **Python 3.8+** | ✅ | Orchestrator uses **stdlib only** — no `pip install` needed |
| **masscan** | ✅ (Phase 1) | `sudo apt install masscan`, or build from source for a newer version |
| **Go 1.22+** | ✅ (Phase 2) | Only for compiling the prober — from [go.dev/dl](https://go.dev/dl) |
| naabu | ➖ Optional | Alternative L4 engine (`--l4-engine naabu`) |
| httpx | ➖ Optional | Fallback L7 engine if you can't compile the prober |
| mmh3 (pip) | ➖ Optional | Only for `tools/favicon_hash.py` |

## 🚀 Installation & Build

```bash
# Phase 1 engine
sudo apt install masscan
# or build the latest from source:
git clone https://github.com/robertdavidgraham/masscan && cd masscan && make

# Phase 2 prober
cd go_prober
go mod tidy        # downloads deps: utls, brotli, zstd, murmur3
go build -o prober .
```

No Go toolchain? The orchestrator falls back to **httpx** automatically:

```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Masscan needs **root / CAP_NET_RAW** for SYN scanning:

```bash
sudo python3 orchestrator.py 10.0.0.0/16
```

## ⚡ Quick Start

```bash
# Simplest run
sudo python3 orchestrator.py 10.0.0.0/16

# Custom ports and rate
sudo python3 orchestrator.py 10.0.0.0/16 -p 80,443,8080,8443 --masscan-rate 3000

# See the execution plan first — zero packets sent
python3 orchestrator.py 10.0.0.0/16 --dry-run
```

Outputs (default prefix `scan_<timestamp>`, customize with `--out`):

| File | Content |
|---|---|
| `scan_*_masscan.txt` | Raw Phase 1 results |
| `scan_*_prober.jsonl` | Phase 2 line-delimited JSON |
| `scan_*_results.csv` | Final table (opens in Excel) |
| `scan_*_report.html` | Interactive HTML report |
| `scan_*_summary.txt` | Text summary |
| `scan_*_diff.txt` | Only when `--diff` is used |

> 🛡️ All of these are covered by the repository's `.gitignore` — scan results contain internal IPs and should never be committed.

## 📖 Key Scenarios

### A) Periodic scans + change report (asset drift)

```bash
# First run
sudo python3 orchestrator.py 10.0.0.0/16 --out scan_monday --rdns

# Next week — new / removed / changed assets vs. the previous scan
sudo python3 orchestrator.py 10.0.0.0/16 --out scan_next --diff scan_monday_results.csv
```

### B) Resume an interrupted scan

```bash
sudo python3 orchestrator.py --resume scan_monday
# If masscan output exists, Phase 1 is skipped and only
# not-yet-probed targets are re-probed.
```

### C) Distributed scan across several servers (very large ranges)

```bash
# Server 1 of 4
sudo python3 orchestrator.py 10.0.0.0/8 --shard 1/4 --out s1
# Server 2 of 4
sudo python3 orchestrator.py 10.0.0.0/8 --shard 2/4 --out s2
```

Both masscan (native `--shard` flag) and the prober (matching FNV filter) respect the shard. Side benefit: each server presents a different source IP, which makes in-network DoS policies far less twitchy.

### D) Teach it your appliances (favicon DB)

```bash
pip install mmh3
cd tools
python3 favicon_hash.py https://10.10.0.1 --add "FortiGate Login" "Network Device" --db ../configs/favicon_db.json
python3 favicon_hash.py https://10.10.0.2:8443 --add "vCenter" "Virtualization" --db ../configs/favicon_db.json
```

From now on, any device with the same favicon is named directly in the output and HTML report. Repeated unlabeled hashes are listed in the summary so you can label them too.

### E) Extra stealth with proxies / source IPs

```bash
sudo python3 orchestrator.py 10.0.0.0/16 \
    --source-ips src_ips.txt        # multiple IPs on this server — rotation
# or
sudo python3 orchestrator.py 10.0.0.0/16 \
    --proxy proxies.txt             # socks5://user:pass@host:1080 or http://...
```

> 🔐 `proxies.txt` may contain credentials and `src_ips.txt` reveals your infrastructure — both are in `.gitignore` on purpose. Keep them out of your repo.

### F) Telegram notifications

```bash
sudo python3 orchestrator.py 10.0.0.0/16 \
    --notify-token 123456:ABC-DEF... --notify-chat -1001234567890
```

## 🥷 Stealth Layers

| Layer | Mechanism |
|---|---|
| L4 | Low rate (`rate` in conf), `--randomize-hosts`, random ephemeral source ports, tuned `--wait`/`--retries`, sensitive-range excludes |
| L7 | Real browser TLS fingerprint (uTLS), exact browser header order, stable per-IP UA, jitter + think time, 15 s rate ramp-up, favicon fetched on the same keep-alive connection inside the rate limiter |
| Adaptive | Circuit breaker: rising error rate (a sign of WAF throttling) → automatic rate halving; recovery → ramp back up |
| Coverage | Automatic second pass for transient errors (timeout/reset/…) with a different profile |

Notes worth knowing:

- **TTL:** stock masscan sends TTL 255 and it's not configurable without patching the source. Keep it in mind for forensic analysis.
- **FortiGate DoS policy:** the `tcp_syn_flood` threshold is usually per-source-IP; 5000 pps from one server will very likely log/alert. For maximum quietness: drop the rate to 500–1000 and use multi-server sharding.
- **HTTP/2:** the prober deliberately pins ALPN to `http/1.1` (otherwise h2-only servers would fail). This trades a small fingerprint-fidelity cost for full coverage.

## 🎛️ Orchestrator Flags

```text
Targets:
  targets...               ranges (CIDR, dash range, single IP) — e.g. 10.0.0.0/16, 10.0.0.1-250
  -f FILE                  file of ranges (one per line)
  -e / --exclude           excluded ranges/IPs (single IPs work too)
  -p PORTS                 web ports (default: 80,443,8000,8080,8081,8443,8888,9090,10443)

Phase 1:
  --l4-engine              masscan | naabu | auto
  --masscan-rate N         packets per second (default 5000)
  --masscan-wait N         seconds to wait for replies (default 5)
  --masscan-retries N      retries (default 2)
  --shard i/n              distributed scan
  --phase1-input FILE      skip Phase 1 and use a ready-made list
  --interface IFACE        network interface

Phase 2:
  --engine                 go | httpx | auto
  --concurrency N          parallel workers (default 200)
  --l7-rate N              max requests/second (default 500)
  --browser                chrome | firefox | edge | random
  --no-adaptive            disable the circuit breaker
  --no-retry               disable the second pass
  --no-favicon             disable favicon hashing

Output & features:
  --out PREFIX             output file prefix
  --resume PREFIX          resume a previous scan
  --diff prev.csv          change report vs. previous scan
  --rdns                   resolve PTR records for IPs with web services
  --no-html                skip the HTML report
  --notify-token/-chat     Telegram
  --dry-run                show the plan only
```

Standalone prober flags: `./prober -h`

## 🧪 Post-Build Health Checks

```bash
# 1) Syntax and help
python3 orchestrator.py --help

# 2) Is the masscan config valid?
sudo masscan -c configs/masscan_stealth.conf --echo

# 3) Prober alone against one host:
echo "10.10.0.1:443" | ./go_prober/prober -o - | python3 -m json.tool

# 4) Full dry-run:
python3 orchestrator.py 10.10.0.0/24 --dry-run
```

## 🗂️ Project Structure

```
├── orchestrator.py            ← main entry point (v3.0)
├── go_prober/
│   ├── prober.go              ← L7 prober source (v3.0)
│   └── go.mod
├── configs/
│   ├── masscan_stealth.conf   ← masscan config (validated with --echo)
│   └── favicon_db.json        ← appliance favicon-hash DB
├── tools/
│   └── favicon_hash.py        ← hash builder for the favicon DB
├── README.md                  ← this file
└── README.fa.md               ← Persian version
```

After building, `go_prober/prober` (the compiled binary) appears here too — it's git-ignored, since every user builds it for their own platform.

## 🛠️ Changelog — v2 → v3 Fixes

| # | Bug | Effect in v2 | Status |
|---|---|---|:---:|
| 1 | masscan `-oG` output parser | Always discovered 0 ports — pipeline broke | ✅ |
| 2 | Non-existent `--excludeclip` flag | masscan died instantly | ✅ |
| 3 | No gzip/br/zstd body decompression | Empty titles on many hosts | ✅ |
| 4 | ALPN negotiated to h2 | Strict HTTPS hosts failed | ✅ |
| 5 | New `bufio.Reader` per hop | Corrupt responses on keep-alive redirects | ✅ |
| 6 | 8000-second timeout in the httpx path | Phase 2 hung forever | ✅ |
| 7 | Fixed 2-hour masscan timeout | Large-range scans killed mid-run | ✅ dynamic timeout |
| 8 | Dead `--resume` argument | Resume didn't work at all | ✅ |

## 🙏 Acknowledgments

- [masscan](https://github.com/robertdavidgraham/masscan) — the fastest TCP port scanner on Earth
- [uTLS / refraction-networking](https://github.com/refraction-networking/utls) — real-world TLS fingerprints for Go
- [projectdiscovery](https://github.com/projectdiscovery) — httpx & naabu
- [Shodan](https://www.shodan.io/) — the mmh3 favicon-hash concept
