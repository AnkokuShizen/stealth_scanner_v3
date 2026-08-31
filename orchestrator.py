#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stealth Asset Scanner — Orchestrator v3.0
==========================================
معماری دو مرحله‌ای برای حداکثر سرعت و پنهان‌کاری:

  فاز ۱ (L4): Masscan/naabu SYN Scan — کشف پورت‌های باز
  فاز ۲ (L7): Go Prober v3 — پروب HTTP با TLS fingerprint مرورگر

تغییرات v3 نسبت به v2:
  [فاز ۰ — باگ‌فیکس]
  - پارسر خروجی masscan: حالا فرمت grepable (-oG) درست پارس می‌شود
    (قبلاً فقط regex خروجی کنسول بود و همیشه ۰ پورت برمی‌گشت!)
  - فلاگ اشتباه --excludeclip → --exclude
  - exclude تک-IP و رنجی هم پشتیبانی می‌شود
  - timeout پویا برای masscan بر اساس حجم واقعی اسکن (قبلاً ۲ ساعت
    ثابت بود و برای رنج‌های بزرگ وسط کار kill می‌شد)
  - باگ واحد timeout در مسیر httpx (۸۰۰۰ ثانیه!)
  - --resume واقعاً پیاده‌سازی شد (قبلاً آرگومان مرده بود)

  [فاز ۱ — Stealth]
  - preflight اعتبارسنجی کانفیگ masscan با --echo (کلید نامعتبر مثل
    ttl کل masscan را قبل از اسکن می‌کُشت)
  - tune کردن wait/retries برای شبکه داخلی
  - adaptive rate و favicon درون rate limiter در prober v3

  [فاز ۲ — فیچرها]
  - favicon mmh3 hash (فرمت شودان) + DB appliance ها
  - تشخیص تکنولوژی: X-Powered-By، generator، کوکی‌ها، WWW-Authenticate
  - --diff: گزارش asset های جدید/حذف‌شده/عوض‌شده نسبت به اسکن قبلی
  - گزارش HTML تک‌فایل با جدول sortable
  - --rdns: حل PTR record برای IP های دارای وب
  - shard توزیع‌شده: --shard 2/8 روی چند سرور
  - naabu به عنوان موتور جایگزین فاز ۱
  - --notify: ارسال خلاصه به Telegram
  - --dry-run: نمایش پلن اجرا بدون اسکن

مثال‌ها:
  python3 orchestrator.py 10.0.0.0/16
  python3 orchestrator.py 10.0.0.0/16 -p 80,443,8080 --masscan-rate 10000
  python3 orchestrator.py 10.0.0.0/16 --proxy proxies.txt --source-ips src_ips.txt
  python3 orchestrator.py --resume scan_20240101_120000
  python3 orchestrator.py 10.0.0.0/16 --diff prev_results.csv --rdns --html
  python3 orchestrator.py 10.0.0.0/8 --shard 2/4   # سرور دوم از ۴ سرور
  python3 orchestrator.py 10.0.0.0/16 --dry-run

⚠ فقط روی رنج‌هایی با مجوز رسمی تست استفاده کنید.
"""

import argparse
import csv
import html as html_lib
import io
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

try:
    from proxy_pool import ProxyPool
    HAS_PROXY_POOL = True
except ImportError:
    HAS_PROXY_POOL = False

VERSION = "3.0-orchestrator"
DEFAULT_PORTS = "80,443,8000,8080,8081,8443,8888,9090,10443"

# ── پارسرها ──
# فرمت کنسول: Discovered open port 80/tcp on 10.0.0.5
MASSCAN_RE = re.compile(r'Discovered open port (\d+)/(?:tcp|udp) on ([\d.]+)')
# فرمت grepable (-oG): Host: 10.0.0.5 ()  Ports: 80/open/tcp//,443/open/tcp//
GREPABLE_RE = re.compile(r'Host:\s*([\d.]+)\s*\(\)\s+Ports:\s*(.+)')
PORT_OPEN_RE = re.compile(r'(\d+)/open')
NAABU_JSON_RE = re.compile(r'^\{.*\}$')

CSV_COLS = ["ip", "hostname", "port", "scheme", "status_code", "title", "server",
            "category", "powered_by", "generator", "cookies", "www_auth",
            "internal_ips", "redirects", "cert_cn", "cert_san",
            "favicon_hash", "favicon_app", "note", "elapsed_ms", "scanned_at"]

CATEGORY_RULES = [
    ("IP Camera", ["hikvision", "dahua", "cctv", "ivms-", "ip camera"]),
    ("Webmail", ["webmail", "roundcube", "zimbra", "outlook", "owa", "mailbox"]),
    ("DevOps", ["jenkins", "gitlab", "grafana", "prometheus", "kibana", "elasticsearch",
                "sonarqube", "nexus", "harbor", "portainer", "rancher", "kubernetes",
                "docker", "argocd", "keycloak"]),
    ("Virtualization", ["vmware", "vcenter", "esxi", "vsphere", "proxmox", "hyper-v",
                        "ovirt", "xen", "openstack"]),
    ("Database Admin", ["phpmyadmin", "pgadmin", "adminer", "mysql", "postgresql",
                        "mongo express", "redis"]),
    ("Storage/NAS", ["synology", "qnap", "truenas", "freenas", "openmediavault"]),
    ("Network Device", ["mikrotik", "routeros", "router", "firewall", "forti", "cisco",
                        "huawei", "zyxel", "tp-link", "tplink", "tenda", "netis",
                        "gateway", "pfsense", "opnsense", "juniper", "edgeos", "vpn",
                        "switch", "load balancer", "loadbalancer", "fortigate",
                        "fortiweb", "sonicwall", "sophos", "watchguard"]),
    ("Printers", ["printer", "kyocera", "ricoh", "xerox", "brother", "canon"]),
    ("Login/Admin", ["login", "log in", "sign in", "signin",
                     "password", "admin", "dashboard", "authentication", "control panel"]),
]

LOCAL_IPS = set()


def log(msg):
    print(msg, flush=True)


def now_iso(ts=None):
    if ts:
        try:
            return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def fmt_dur(sec):
    sec = int(sec)
    return f"{sec // 3600:02d}:{(sec % 3600) // 60:02d}:{sec % 60:02d}"


def detect_local_ips():
    ips = set()
    for dst in ("8.8.8.8", "4.2.2.4", "10.10.10.10"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((dst, 53))
            ips.add(s.getsockname()[0])
        except Exception:
            pass
        finally:
            s.close()
    ips.discard("0.0.0.0")
    return ips


def classify(title, server, cert_cn):
    hay = f"{title} {server} {cert_cn}".lower()
    for name, kws in CATEGORY_RULES:
        if any(kw in hay for kw in kws):
            return name
    return "Generic Web"


def check_tool(name, cmd):
    """بررسی وجود ابزار در سیستم"""
    return shutil.which(cmd) is not None


# ═══════════════════════════════════════════════════════════════
# Target Ranges
# ═══════════════════════════════════════════════════════════════

def _tokens(spec):
    return [t for t in re.split(r"[,\s]+", (spec or "").strip()) if t]


def expand_target_ranges(targets, exclude_ranges):
    """تبدیل رنج‌ها به لیست CIDR — با پشتیبانی کامل exclude (تک-IP هم)"""
    cidrs = []
    for spec in targets:
        for token in _tokens(spec):
            if '-' in token and '/' not in token:
                parts = token.split('-')
                if len(parts) == 2:
                    try:
                        start = ipaddress.ip_address(parts[0].strip())
                        # فرم کوتاه: 10.0.0.1-250
                        if parts[1].strip().isdigit():
                            base = str(start).rsplit('.', 1)[0]
                            end = ipaddress.ip_address(f"{base}.{parts[1].strip()}")
                        else:
                            end = ipaddress.ip_address(parts[1].strip())
                        nets = ipaddress.summarize_address_range(start, end)
                        cidrs.extend(str(n) for n in nets)
                    except Exception as e:
                        log(f"[!] invalid range: {token} -> {e}")
            elif '/' in token:
                try:
                    net = ipaddress.ip_network(token, strict=False)
                    if net.version == 4:
                        cidrs.append(str(net))
                except Exception as e:
                    log(f"[!] invalid CIDR: {token} -> {e}")
            else:
                # تک-IP
                try:
                    ipaddress.ip_address(token)
                    cidrs.append(token + "/32")
                except Exception:
                    log(f"[!] invalid target: {token}")

    excl_cidrs = []
    for spec in exclude_ranges or []:
        for token in _tokens(spec):
            if '-' in token and '/' not in token:
                parts = token.split('-')
                if len(parts) == 2:
                    try:
                        start = ipaddress.ip_address(parts[0].strip())
                        if parts[1].strip().isdigit():
                            base = str(start).rsplit('.', 1)[0]
                            end = ipaddress.ip_address(f"{base}.{parts[1].strip()}")
                        else:
                            end = ipaddress.ip_address(parts[1].strip())
                        excl_cidrs.extend(str(n) for n in
                                          ipaddress.summarize_address_range(start, end))
                    except Exception as e:
                        log(f"[!] invalid exclude range: {token} -> {e}")
            elif '/' in token:
                try:
                    ipaddress.ip_network(token, strict=False)
                    excl_cidrs.append(token)
                except Exception as e:
                    log(f"[!] invalid exclude CIDR: {token} -> {e}")
            else:
                try:
                    ipaddress.ip_address(token)
                    excl_cidrs.append(token + "/32")
                except Exception:
                    log(f"[!] invalid exclude: {token}")

    return cidrs, excl_cidrs


def count_ips_in_ranges(cidrs):
    total = 0
    for c in cidrs:
        try:
            total += ipaddress.ip_network(c, strict=False).num_addresses
        except Exception:
            pass
    return total


def fnv32a(s):
    """FNV-1a 32-bit — همسان با fnv32a در Go prober"""
    h = 2166136261
    for ch in s.encode():
        h ^= ch
        h = (h * 16777619) & 0xFFFFFFFF
    return h


# ═══════════════════════════════════════════════════════════════
# Masscan Config Preflight (فاز ۱)
# ═══════════════════════════════════════════════════════════════

def validate_masscan_conf(masscan_path, conf_file):
    """کلید نامعتبر در کانفیگ (مثل ttl در خیلی از buildها) کل masscan را
    fatal می‌کند. با --echo قبل از اسکن اعتبارسنجی می‌کنیم."""
    if not conf_file or not os.path.exists(conf_file):
        return False, "config file not found"
    try:
        r = subprocess.run([masscan_path, "-c", conf_file, "--echo"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return True, ""
        return False, (r.stderr or r.stdout or "unknown error").strip()[:300]
    except Exception as e:
        return False, str(e)[:300]


# ═══════════════════════════════════════════════════════════════
# Phase 1: L4 Scan (Masscan / naabu)
# ═══════════════════════════════════════════════════════════════

def build_masscan_cmd(cidrs, ports, rate, exclude, output_file,
                      masscan_path="masscan", config_file=None, interface=None,
                      wait=5, retries=2, shard=None, shards=1):
    target_str = " ".join(cidrs)
    cmd = [masscan_path, target_str]

    # ⚠ ترتیب مهم است: کانفیگ اول می‌آید تا آرگومان‌های CLI بعدی
    # (rate/wait/retries) مقادیر داخل کانفیگ را override کنند
    if config_file:
        cmd.extend(["-c", config_file])

    cmd.extend(["-p", ports, "--rate", str(rate),
                "--randomize-hosts", "-oG", output_file])

    if interface:
        cmd.extend(["-e", interface])

    # فیکس v3: فلاگ درست --exclude (قبلاً --excludeclip بود و masscan را
    # fatal می‌کرد)
    for e in exclude:
        cmd.extend(["--exclude", e])

    # tune برای شبکه داخلی
    cmd.extend(["--wait", str(wait)])
    if retries and retries > 0:
        cmd.extend(["--retries", str(retries)])

    if shards and shards > 1 and shard:
        cmd.extend(["--shard", f"{shard}/{shards}"])

    return cmd


def run_masscan(cidrs, ports, rate, exclude, output_file, **kw):
    """اجرای Masscan با timeout پویا بر اساس حجم واقعی اسکن"""
    cmd = build_masscan_cmd(cidrs, ports, rate, exclude, output_file, **kw)

    log(f"[Phase 1] Masscan: {len(cidrs)} CIDR blocks | Ports: {ports} | Rate: {rate} pps")
    log(f"[Phase 1] Command: {' '.join(cmd[:8])}...")

    # timeout پویا (فیکس v3: قبلاً ۲ ساعت ثابت بود)
    total_probes = count_ips_in_ranges(cidrs) * len(ports.split(','))
    est_sec = total_probes / rate if rate > 0 else 0
    wait_s = kw.get('wait', 5) or 5
    mc_timeout = max(1800, int(est_sec * 1.5) + int(wait_s) + 300)
    log(f"[Phase 1] Estimated {total_probes:,} probes -> {fmt_dur(est_sec)} "
        f"(hard timeout: {fmt_dur(mc_timeout)})")

    t0 = time.monotonic()
    stdout_text = ""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=mc_timeout)
        stdout_text = result.stdout or ""
        if result.returncode != 0:
            log(f"[Phase 1] Masscan stderr: {(result.stderr or '')[:500]}")
    except subprocess.TimeoutExpired:
        log("[Phase 1] Masscan hard timeout — parsing partial results")
    except FileNotFoundError:
        log(f"[!] masscan not found. Install: apt install masscan")
        log("[!] Alternative: --l4-engine naabu  یا  --phase1-input <file>")
        sys.exit(2)

    elapsed = time.monotonic() - t0
    open_ports = load_open_ports(output_file, extra_text=stdout_text)
    log(f"[Phase 1] Done in {fmt_dur(elapsed)}: {len(open_ports):,} open ports")
    return open_ports


def run_naabu(cidrs, ports, rate, exclude, output_file, naabu_path="naabu",
              shard=None, shards=1):
    """موتور جایگزین فاز ۱ — naabu (projectdiscovery)"""
    ranges_file = output_file.replace('.txt', '_ranges.txt')
    with open(ranges_file, 'w') as f:
        f.write("\n".join(cidrs) + "\n")

    cmd = [naabu_path, "-l", ranges_file, "-p", ports, "-rate", str(rate),
           "-json", "-silent", "-o", output_file]
    if shards and shards > 1 and shard:
        log("[!] naabu shard پشتیبانی نمی‌شود — فیلتر shard در پایتون اعمال می‌شود")

    log(f"[Phase 1] naabu: {len(cidrs)} CIDR blocks | Rate: {rate} pps")
    t0 = time.monotonic()
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=86400)
    except FileNotFoundError:
        log("[!] naabu not found. Install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
        sys.exit(2)
    except subprocess.TimeoutExpired:
        log("[Phase 1] naabu hard timeout — parsing partial results")

    open_ports = []
    excl_nets = []
    for c in exclude:
        try:
            excl_nets.append(ipaddress.ip_network(c, strict=False))
        except Exception:
            pass

    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                ip, port = None, None
                if line.startswith('{'):
                    try:
                        j = json.loads(line)
                        ip = j.get('ip') or j.get('host')
                        port = j.get('port')
                    except Exception:
                        pass
                elif ':' in line:
                    ip, p = line.rsplit(':', 1)
                    if p.isdigit():
                        port = int(p)
                if not ip or not port:
                    continue
                ip = str(ip).strip()
                try:
                    ipo = ipaddress.ip_address(ip)
                except Exception:
                    continue
                if any(ipo in n for n in excl_nets):
                    continue
                # فیلتر shard (همان الگوریتم Go)
                if shards and shards > 1 and shard:
                    if fnv32a(f"{ip}:{port}") % shards != shard - 1:
                        continue
                open_ports.append((ip, int(port)))

    open_ports = sorted(set(open_ports))
    elapsed = time.monotonic() - t0
    log(f"[Phase 1] Done in {fmt_dur(elapsed)}: {len(open_ports):,} open ports")
    return open_ports


def load_open_ports(path, extra_text=""):
    """پارس خروجی masscan — حالا هر دو فرمت grepable و کنسول + plain ip:port
    (فیکس بحرانی v3: قبلاً فرمت -oG اصلاً پارس نمی‌شد و همیشه صفر برمی‌گشت)"""
    ports = []

    def _parse_line(line, out):
        line = line.strip()
        if not line or line.startswith('#'):
            return
        m = MASSCAN_RE.search(line)          # کنسول
        if m:
            out.append((m.group(2), int(m.group(1))))
            return
        m = GREPABLE_RE.search(line)         # grepable -oG
        if m:
            ip, ports_field = m.group(1), m.group(2)
            for item in ports_field.split(','):
                pm = PORT_OPEN_RE.search(item)
                if pm:
                    out.append((ip, int(pm.group(1))))
            return
        if ':' in line:                       # plain ip:port
            parts = line.split(':')
            if len(parts) == 2 and parts[1].strip().isdigit():
                out.append((parts[0], int(parts[1])))

    if path and os.path.exists(path):
        with open(path, 'r', errors='replace') as f:
            for line in f:
                _parse_line(line, ports)

    # خروجی کنسول هم به عنوان پشتیبان پارس می‌شود
    if extra_text:
        for line in extra_text.splitlines():
            _parse_line(line, ports)

    return sorted(set(ports))


# ═══════════════════════════════════════════════════════════════
# Phase 2: Go L7 Prober
# ═══════════════════════════════════════════════════════════════

def run_go_prober(open_ports, prober_bin, output_file, cfg):
    """اجرای Go L7 Prober v3"""
    targets_file = output_file.replace('.jsonl', '_targets.txt')
    with open(targets_file, 'w') as f:
        for ip, port in open_ports:
            f.write(f"{ip}:{port}\n")

    cmd = [
        prober_bin,
        "-i", targets_file,
        "-o", output_file,
        "-c", str(cfg.get('concurrency', 200)),
        "-rate", str(cfg.get('rate', 500)),
        "-timeout", str(cfg.get('timeout', 8000)),
        "-jitter", str(cfg.get('jitter', 20)),
        "-think", str(cfg.get('think_time', 50)),
        "-browser", cfg.get('browser', 'random'),
        "-max-body", str(cfg.get('max_body', 131072)),
        "-max-redirects", str(cfg.get('max_redirects', 3)),
    ]

    # فلاگ‌های بولی در Go باید به شکل -flag=true/false پاس داده شوند
    cmd.append(f"-favicon={'true' if cfg.get('favicon', True) else 'false'}")
    cmd.append(f"-adaptive={'true' if cfg.get('adaptive', True) else 'false'}")
    cmd.append(f"-retry={'true' if cfg.get('retry', True) else 'false'}")

    if cfg.get('favicon_db') and os.path.exists(cfg['favicon_db']):
        cmd.extend(["-favicon-db", cfg['favicon_db']])

    if cfg.get('shards', 1) > 1:
        cmd.extend(["-shard", str(cfg.get('shard', 1)), "-shards", str(cfg['shards'])])

    if cfg.get('proxy_file'):
        cmd.extend(["-proxy", cfg['proxy_file']])
    if cfg.get('source_ips_file'):
        cmd.extend(["-source-ips", cfg['source_ips_file']])

    log(f"[Phase 2] Go Prober: {len(open_ports):,} targets, {cfg.get('concurrency', 200)} workers")
    log(f"[Phase 2] Command: {' '.join(cmd[:10])}...")

    # timeout پویا + لحاظ کردن پاس retry
    rate = cfg.get('rate', 500) or 0
    if rate > 0:
        est = len(open_ports) / rate * 2.2   # ×۲.۲ برای پاس دوم
        pb_timeout = max(3600, int(est) + 900)
    else:
        pb_timeout = 4 * 3600

    t0 = time.monotonic()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=pb_timeout)
        if result.returncode != 0:
            log(f"[Phase 2] Prober stderr: {(result.stderr or '')[:500]}")
    except subprocess.TimeoutExpired:
        log("[Phase 2] Prober hard timeout — parsing partial results")
    except FileNotFoundError:
        log(f"[!] Go prober not found: {prober_bin}")
        log(f"[!] Build it: cd go_prober && go mod tidy && go build -o {prober_bin} .")
        sys.exit(2)

    elapsed = time.monotonic() - t0
    log(f"[Phase 2] Done in {fmt_dur(elapsed)}")
    return elapsed


# ═══════════════════════════════════════════════════════════════
# Phase 2 Alternative: httpx
# ═══════════════════════════════════════════════════════════════

def run_httpx(open_ports, output_file, cfg):
    """اجرای httpx به عنوان fallback (بدون نیاز به کامپایل)
    فیکس v3: timeout از ms به ثانیه تبدیل می‌شود (قبلاً ۸۰۰۰ ثانیه بود!)"""
    targets_file = output_file.replace('.jsonl', '_targets.txt')
    with open(targets_file, 'w') as f:
        for ip, port in open_ports:
            f.write(f"{ip}:{port}\n")

    cmd = [
        "httpx",
        "-l", targets_file,
        "-o", output_file,
        "-json", "-no-color",
        "-status-code", "-title", "-web-server", "-tech-detect",
        "-follow-redirects",
        "-timeout", str(max(1, int(cfg.get('timeout', 8000)) // 1000)),  # ms → s
        "-rl", str(cfg.get('rate', 200)),
        "-c", str(cfg.get('concurrency', 100)),
        "-random-agent",
    ]

    if cfg.get('proxy_file'):
        cmd.extend(["-http-proxy", cfg['proxy_file']])

    log(f"[Phase 2 - httpx] {len(open_ports):,} targets")
    t0 = time.monotonic()
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=14400)
    except FileNotFoundError:
        log("[!] httpx not found. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        sys.exit(2)
    elapsed = time.monotonic() - t0
    log(f"[Phase 2 - httpx] Done in {fmt_dur(elapsed)}")
    return elapsed


def httpx_rows(jsonl_file):
    """تبدیل خروجی JSON خطی httpx به schema داخلی"""
    rows = []
    if not os.path.exists(jsonl_file):
        return rows
    with open(jsonl_file, 'r', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line.startswith('{'):
                continue
            try:
                j = json.loads(line)
            except Exception:
                continue
            url = j.get('url') or ''
            m = re.match(r'^(https?)://([^/:]+)(?::(\d+))?', url)
            scheme = j.get('scheme')
            host = j.get('host')
            port = j.get('port')
            if m and (not host or not port):
                scheme, host, port = m.group(1), m.group(2), m.group(3)
            if not host:
                continue
            try:
                port = int(port)
            except Exception:
                port = 443 if scheme == 'https' else 80
            tech = j.get('tech') or []
            rows.append({
                'ip': str(host), 'port': port, 'scheme': scheme or '',
                'status_code': j.get('status_code') or 0,
                'title': (j.get('title') or '')[:200],
                'server': j.get('webserver') or '',
                'generator': ", ".join(tech[:5]) if tech else '',
                'internal_ips': '', 'cert_cn': '', 'cert_san': '',
                'elapsed_ms': '', 'ts': '',
                'error': '' if not j.get('failed') else 'failed',
            })
    return rows
# ═══════════════════════════════════════════════════════════════
# Result Processing
# ═══════════════════════════════════════════════════════════════

def load_jsonl_rows(jsonl_file):
    rows = []
    if not os.path.exists(jsonl_file):
        return rows
    with open(jsonl_file, 'r', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def dedupe_rows(rows):
    """حذف تکراری (ip,port) — اولویت با نتیجه موفق؛ پاس retry نتایج را
    append می‌کند و باید نسخه موفق جایگزین خطای پاس اول شود."""
    best = {}
    for r in rows:
        key = (str(r.get('ip', '')), str(r.get('port', '')))
        old = best.get(key)
        if old is None:
            best[key] = r
        elif old.get('error') and not r.get('error'):
            best[key] = r
        elif not old.get('error') and not r.get('error'):
            best[key] = r  # نسخه جدیدتر (پاس retry)
    return list(best.values())


def rdns_enrich(rows, max_workers=16):
    """حل PTR record برای IP های دارای وب — ستون hostname"""
    ips = sorted({r['ip'] for r in rows if r.get('scheme') and r.get('ip')})
    if not ips:
        return 0
    log(f"[rdns] resolving PTR for {len(ips):,} unique IPs...")

    def lookup(ip):
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip, ""

    resolved = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for ip, name in ex.map(lookup, ips):
            resolved[ip] = name
    for r in rows:
        r['hostname'] = resolved.get(r.get('ip', ''), "")
    found = sum(1 for v in resolved.values() if v)
    log(f"[rdns] resolved {found:,}/{len(ips):,}")
    return found


# ═══════════════════════════════════════════════════════════════
# Scan Diff (فاز ۲)
# ═══════════════════════════════════════════════════════════════

def load_prev_state(csv_path):
    prev = {}
    try:
        with open(csv_path, encoding='utf-8-sig') as f:
            for r in csv.DictReader(f):
                if r.get('scheme'):
                    prev[(r.get('ip', ''), str(r.get('port', '')))] = \
                        (r.get('title', '') or '', r.get('category', '') or '')
    except FileNotFoundError:
        log(f"[!] diff: previous results not found: {csv_path}")
    except Exception as e:
        log(f"[!] diff: cannot load {csv_path}: {e}")
    return prev


def diff_scans(cur_rows, prev_csv, diff_file):
    """گزارش asset های جدید / حذف‌شده / تایتل-عوض‌شده نسبت به اسکن قبلی"""
    prev = load_prev_state(prev_csv)
    cur = {}
    for r in cur_rows:
        if r.get('scheme'):
            cur[(r.get('ip', ''), str(r.get('port', '')))] = \
                (r.get('title', '') or '', classify(r.get('title', ''),
                                                    r.get('server', ''),
                                                    r.get('cert_cn', '')))

    new_keys = sorted(set(cur) - set(prev), key=lambda k: (k[0], int(k[1] or 0)))
    gone_keys = sorted(set(prev) - set(cur), key=lambda k: (k[0], int(k[1] or 0)))
    changed_keys = sorted(
        (k for k in set(cur) & set(prev) if cur[k][0] != prev[k][0] and cur[k][0]),
        key=lambda k: (k[0], int(k[1] or 0)))

    L = []
    L.append("=" * 70)
    L.append(f"Scan Diff — vs {prev_csv}")
    L.append(f"Generated: {now_iso()}")
    L.append("=" * 70)
    L.append(f"New services: {len(new_keys):,}")
    L.append(f"Removed services: {len(gone_keys):,}")
    L.append(f"Changed titles: {len(changed_keys):,}")
    L.append("")

    if new_keys:
        L.append("--- NEW (not in previous scan) ---")
        for k in new_keys[:2000]:
            t, c = cur[k]
            L.append(f"  + {k[0]}:{k[1]}  [{c}]  {t[:70]}")
        if len(new_keys) > 2000:
            L.append(f"  ... and {len(new_keys) - 2000:,} more")
        L.append("")

    if gone_keys:
        L.append("--- REMOVED (was in previous scan, now gone) ---")
        for k in gone_keys[:2000]:
            t, c = prev[k]
            L.append(f"  - {k[0]}:{k[1]}  [{c}]  {t[:70]}")
        if len(gone_keys) > 2000:
            L.append(f"  ... and {len(gone_keys) - 2000:,} more")
        L.append("")

    if changed_keys:
        L.append("--- CHANGED TITLE ---")
        for k in changed_keys[:2000]:
            L.append(f"  ~ {k[0]}:{k[1]}  '{prev[k][0][:40]}' -> '{cur[k][0][:40]}'")
        if len(changed_keys) > 2000:
            L.append(f"  ... and {len(changed_keys) - 2000:,} more")
        L.append("")

    text = "\n".join(L)
    with open(diff_file, 'w', encoding='utf-8') as f:
        f.write(text)
    log(f"[diff] {len(new_keys):,} new | {len(gone_keys):,} removed | "
        f"{len(changed_keys):,} changed -> {diff_file}")
    return {'new': len(new_keys), 'gone': len(gone_keys), 'changed': len(changed_keys)}


# ═══════════════════════════════════════════════════════════════
# Summary + CSV
# ═══════════════════════════════════════════════════════════════

def process_results(rows, csv_file, summary_file, meta=None):
    """ساخت CSV + خلاصه متنی از ردیف‌های پاکسازی‌شده"""
    web = [r for r in rows if r.get('scheme')]
    errors = [r for r in rows if r.get('error')]

    # Write CSV
    with open(csv_file, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLS, extrasaction='ignore')
        writer.writeheader()
        for r in rows:
            row_out = {
                'ip': r.get('ip', ''),
                'hostname': r.get('hostname', ''),
                'port': r.get('port', ''),
                'scheme': r.get('scheme', ''),
                'status_code': r.get('status_code', ''),
                'title': r.get('title', ''),
                'server': r.get('server', ''),
                'category': classify(r.get('title', ''), r.get('server', ''),
                                     r.get('cert_cn', '')) if r.get('scheme') else '',
                'powered_by': r.get('powered_by', ''),
                'generator': r.get('generator', ''),
                'cookies': r.get('cookies', ''),
                'www_auth': r.get('www_auth', ''),
                'internal_ips': r.get('internal_ips', ''),
                'redirects': r.get('redirects', ''),
                'cert_cn': r.get('cert_cn', ''),
                'cert_san': r.get('cert_san', ''),
                'favicon_hash': r.get('favicon_hash', ''),
                'favicon_app': r.get('favicon_app', ''),
                'note': r.get('error', ''),
                'elapsed_ms': r.get('elapsed_ms', ''),
                'scanned_at': now_iso(r.get('ts')),
            }
            writer.writerow(row_out)

    # Build summary
    L = []
    L.append("=" * 70)
    L.append(f"Stealth Asset Scan Summary v{VERSION}")
    L.append("=" * 70)
    if meta:
        if meta.get('targets'):
            L.append(f"Targets: {meta['targets']}")
        if meta.get('engine'):
            L.append(f"Engine: L4={meta.get('l4', 'masscan')}  L7={meta['engine']}"
                     + (f"  shard {meta.get('shard')}/{meta.get('shards')}"
                        if meta.get('shards', 1) > 1 else ""))
    L.append(f"Total probed: {len(rows):,} | Web services: {len(web):,} | Errors: {len(errors):,}")

    if web:
        byport = Counter(r['port'] for r in web)
        L.append("")
        L.append("--- Ports ---")
        for p, c in byport.most_common():
            L.append(f"  {p}: {c:,}")

        bycode = Counter(r['status_code'] for r in web)
        L.append("")
        L.append("--- HTTP Status ---")
        for s, c in bycode.most_common():
            L.append(f"  {s}: {c:,}")

        bycat = Counter(classify(r.get('title', ''), r.get('server', ''),
                                 r.get('cert_cn', '')) for r in web)
        L.append("")
        L.append("--- Categories ---")
        for cat, c in bycat.most_common():
            L.append(f"  {cat}: {c:,}")

        titles = Counter(r['title'] for r in web if r.get('title'))
        if titles:
            L.append("")
            L.append("--- Top 15 Titles ---")
            for t, c in titles.most_common(15):
                L.append(f"  {c:,} x {t[:80]}")

        servers = Counter(r['server'] for r in web if r.get('server'))
        if servers:
            L.append("")
            L.append("--- Top 10 Servers ---")
            for s, c in servers.most_common(10):
                L.append(f"  {c:,} x {s[:50]}")

        # فاز ۲: tech stacks
        powered = Counter(r['powered_by'] for r in web if r.get('powered_by'))
        if powered:
            L.append("")
            L.append("--- Top X-Powered-By ---")
            for s, c in powered.most_common(10):
                L.append(f"  {c:,} x {s[:60]}")

        gens = Counter(r['generator'] for r in web if r.get('generator'))
        if gens:
            L.append("")
            L.append("--- Top Generators/Tech ---")
            for s, c in gens.most_common(10):
                L.append(f"  {c:,} x {s[:60]}")

        # فاز ۲: favicon appliance ها
        apps = Counter(r['favicon_app'] for r in web if r.get('favicon_app'))
        if apps:
            L.append("")
            L.append("--- Known Appliances (favicon match) ---")
            for s, c in apps.most_common(15):
                L.append(f"  {c:,} x {s[:60]}")

        favs = Counter(r['favicon_hash'] for r in web if r.get('favicon_hash'))
        if favs:
            L.append("")
            L.append("--- Top Favicon Hashes (label them in configs/favicon_db.json) ---")
            for s, c in favs.most_common(15):
                L.append(f"  {c:,} x {s}")

        auths = [r for r in web if r.get('www_auth')]
        if auths:
            L.append("")
            L.append(f"--- HTTP Auth Protected ({len(auths):,}) ---")
            for r in auths[:20]:
                L.append(f"  {r['ip']}:{r['port']}  {r['www_auth'][:60]}")

    leaks = [r for r in web if r.get('internal_ips')]
    L.append("")
    L.append("--- Leaked Internal IPs ---")
    if leaks:
        uniq = Counter()
        for r in leaks:
            for ip in r['internal_ips'].split(', '):
                if ip:
                    uniq[ip] += 1
        L.append(f"Services with leaks: {len(leaks):,} | Unique internal IPs: {len(uniq):,}")
        for r in leaks[:50]:
            L.append(f"  {r['ip']}:{r['port']} ({r['scheme']}) -> {r['internal_ips']}")
        if len(leaks) > 50:
            L.append(f"  ... and {len(leaks) - 50:,} more")
    else:
        L.append("No internal IPs leaked.")

    if errors:
        err_types = Counter(r.get('error', 'unknown') for r in errors)
        L.append("")
        L.append("--- Error Breakdown ---")
        for e, c in err_types.most_common():
            L.append(f"  {e}: {c:,}")

    L.append("")
    L.append("--- Files ---")
    L.append(f"  CSV:     {csv_file}")
    L.append(f"  Summary: {summary_file}")
    L.append("=" * 70)

    summary_text = "\n".join(L)
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write(summary_text)

    return summary_text, len(web), len(errors)


# ═══════════════════════════════════════════════════════════════
# HTML Report (فاز ۲)
# ═══════════════════════════════════════════════════════════════

def generate_html_report(rows, html_file, meta=None):
    """گزارش HTML تک‌فایل (CSS/JS inline) — بدون وابستگی خارجی"""
    esc = html_lib.escape
    web = [r for r in rows if r.get('scheme')]
    bycat = Counter(classify(r.get('title', ''), r.get('server', ''),
                             r.get('cert_cn', '')) for r in web)
    byport = Counter(r['port'] for r in web)
    bycode = Counter(r['status_code'] for r in web)
    apps = Counter(r['favicon_app'] for r in web if r.get('favicon_app'))
    favs = Counter(r['favicon_hash'] for r in web if r.get('favicon_hash'))
    leaks = [r for r in web if r.get('internal_ips')]

    max_port = max(byport.values()) if byport else 1
    max_cat = max(bycat.values()) if bycat else 1

    def bars(counter, mx, color):
        out = []
        for k, c in counter.most_common(12):
            pct = int(c / mx * 100) if mx else 0
            out.append(f'<div class="bar-row"><div class="bar-label">{esc(str(k))}</div>'
                       f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{color}"></div></div>'
                       f'<div class="bar-val">{c:,}</div></div>')
        return "\n".join(out) or '<div class="muted">—</div>'

    table_rows = []
    for r in sorted(web, key=lambda x: (str(x.get('ip', '')), int(x.get('port', 0) or 0))):
        cat = classify(r.get('title', ''), r.get('server', ''), r.get('cert_cn', ''))
        code = r.get('status_code', '')
        code_cls = 'ok' if str(code).startswith('2') else ('warn' if str(code).startswith('3') else 'bad')
        table_rows.append(
            f'<tr><td dir="ltr">{esc(str(r.get("ip", "")))}</td>'
            f'<td dir="ltr">{esc(str(r.get("hostname", "")))}</td>'
            f'<td dir="ltr">{esc(str(r.get("port", "")))}</td>'
            f'<td>{esc(str(r.get("scheme", "")))}</td>'
            f'<td><span class="code {code_cls}">{esc(str(code))}</span></td>'
            f'<td dir="auto">{esc(str(r.get("title", "")))}</td>'
            f'<td dir="auto">{esc(str(r.get("server", "")))}</td>'
            f'<td>{esc(cat)}</td>'
            f'<td dir="auto">{esc(str(r.get("favicon_app", "")))}</td>'
            f'<td dir="auto">{esc(str(r.get("note", "")))}</td></tr>')

    leak_rows = "\n".join(
        f'<tr><td dir="ltr">{esc(r.get("ip", ""))}:{esc(str(r.get("port", "")))}</td>'
        f'<td dir="ltr">{esc(r.get("internal_ips", ""))}</td></tr>'
        for r in leaks[:100]) or '<tr><td colspan="2" class="muted">No internal IPs leaked.</td></tr>'

    fav_html = ""
    if favs:
        fav_html = "<h2>Top Favicon Hashes</h2><p class='muted'>برای label کردن، هش‌ها را در configs/favicon_db.json اضافه کنید.</p>" + bars(favs, max(favs.values()), '#8b9dc3')

    meta_html = ""
    if meta:
        meta_html = (f"<div class='muted'>Targets: {esc(str(meta.get('targets', '')))} &nbsp;|&nbsp; "
                     f"Engine: {esc(str(meta.get('engine', '')))} &nbsp;|&nbsp; "
                     f"Generated: {esc(now_iso())}</div>")

    page = f"""<!DOCTYPE html>
<html lang="fa"><head><meta charset="utf-8">
<title>Stealth Asset Scan Report</title>
<style>
:root{{--bg:#0d1117;--panel:#161b22;--bd:#30363d;--fg:#c9d1d9;--mut:#8b949e;
--acc:#58a6ff;--ok:#3fb950;--warn:#d29922;--bad:#f85149}}
*{{box-sizing:border-box}}body{{background:var(--bg);color:var(--fg);
font-family:'Segoe UI',Tahoma,Vazirmatn,sans-serif;margin:0;padding:24px;line-height:1.5}}
h1{{color:var(--acc);font-size:22px;margin:0 0 4px}}h2{{font-size:16px;color:var(--acc);margin:28px 0 10px}}
.muted{{color:var(--mut);font-size:13px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}}
.card{{background:var(--panel);border:1px solid var(--bd);border-radius:10px;padding:14px 22px;min-width:130px}}
.card .n{{font-size:26px;font-weight:700;color:var(--acc)}}
.card .t{{font-size:12px;color:var(--mut)}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:24px}}
@media(max-width:900px){{.grid{{grid-template-columns:1fr}}}}
.panel{{background:var(--panel);border:1px solid var(--bd);border-radius:10px;padding:16px}}
.bar-row{{display:flex;align-items:center;gap:10px;margin:5px 0}}
.bar-label{{width:190px;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:ltr;text-align:right}}
.bar-track{{flex:1;background:#21262d;border-radius:4px;height:14px}}
.bar-fill{{height:14px;border-radius:4px}}
.bar-val{{width:60px;font-size:12px;color:var(--mut);text-align:left}}
table{{border-collapse:collapse;width:100%;font-size:12.5px}}
th{{background:#21262d;color:var(--acc);padding:8px 10px;text-align:left;cursor:pointer;user-select:none;position:sticky;top:0}}
th:hover{{background:#2d333b}}td{{padding:6px 10px;border-top:1px solid var(--bd)}}
tr:hover td{{background:#1c2129}}
.tbl-wrap{{max-height:520px;overflow:auto;border:1px solid var(--bd);border-radius:8px}}
.code{{padding:1px 8px;border-radius:10px;font-size:11px}}
.code.ok{{background:rgba(63,185,80,.15);color:var(--ok)}}
.code.warn{{background:rgba(210,153,34,.15);color:var(--warn)}}
.code.bad{{background:rgba(248,81,73,.15);color:var(--bad)}}
</style></head><body>
<h1>Stealth Asset Scan Report</h1>
{meta_html}
<div class="cards">
<div class="card"><div class="n">{len(rows):,}</div><div class="t">Probed</div></div>
<div class="card"><div class="n">{len(web):,}</div><div class="t">Web Services</div></div>
<div class="card"><div class="n">{len(bycat)}</div><div class="t">Categories</div></div>
<div class="card"><div class="n">{len(leaks):,}</div><div class="t">IP Leaks</div></div>
<div class="card"><div class="n">{len(byport)}</div><div class="t">Distinct Ports</div></div>
</div>
<div class="grid">
<div class="panel"><h2 style="margin-top:0">Categories</h2>{bars(bycat, max_cat, '#58a6ff')}</div>
<div class="panel"><h2 style="margin-top:0">Ports</h2>{bars(byport, max_port, '#3fb950')}</div>
</div>
<h2>Known Appliances (Favicon Match)</h2>
<div class="panel">{bars(apps, max(apps.values()) if apps else 1, '#d29922')}</div>
{fav_html}
<h2>Leaked Internal IPs</h2>
<div class="tbl-wrap"><table><tr><th>Service</th><th>Leaked IPs</th></tr>{leak_rows}</table></div>
<h2>All Web Services ({len(web):,}) — روی ستون‌ها کلیک کنید تا مرتب شود</h2>
<div class="tbl-wrap"><table id="main">
<tr><th>IP</th><th>Hostname</th><th>Port</th><th>Scheme</th><th>Status</th><th>Title</th><th>Server</th><th>Category</th><th>Appliance</th><th>Note</th></tr>
{''.join(table_rows)}
</table></div>
<script>
document.querySelectorAll('th').forEach(function(th,ti){{
 th.addEventListener('click',function(){{
  var tb=th.closest('table');var rows=Array.from(tb.querySelectorAll('tr')).slice(1);
  var asc=th.dataset.asc!=='1';th.dataset.asc=asc?'1':'0';
  rows.sort(function(a,b){{var x=a.children[ti].innerText,y=b.children[ti].innerText;
   var nx=parseFloat(x),ny=parseFloat(y);if(!isNaN(nx)&&!isNaN(ny)){{return asc?nx-ny:ny-nx}}
   return asc?x.localeCompare(y):y.localeCompare(x)}});
  rows.forEach(function(r){{tb.appendChild(r)}});
 }});
}});
</script>
</body></html>"""

    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(page)
    log(f"[html] report -> {html_file}")


# ═══════════════════════════════════════════════════════════════
# Notifications
# ═══════════════════════════════════════════════════════════════

def notify_telegram(token, chat_id, text):
    if not token or not chat_id:
        return
    try:
        data = urllib.parse.urlencode({'chat_id': chat_id, 'text': text[:3900]}).encode()
        req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data)
        urllib.request.urlopen(req, timeout=15)
        log("[notify] Telegram summary sent")
    except Exception as e:
        log(f"[notify] Telegram failed: {e}")


# ═══════════════════════════════════════════════════════════════
# Main Pipeline
# ═══════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        prog="stealth_scanner",
        description="Two-phase stealth asset scanner (Masscan/naabu + Go L7 Prober v3)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python3 orchestrator.py 10.0.0.0/16

  # Custom ports and rate
  python3 orchestrator.py 10.0.0.0/16 -p 80,443,8080 --masscan-rate 10000

  # With proxy rotation
  python3 orchestrator.py 10.0.0.0/16 --proxy proxies.txt

  # Skip Phase 1, use existing port list
  python3 orchestrator.py --phase1-input open_ports.txt 10.0.0.0/16

  # Resume a previous scan (skips already-probed successful targets)
  python3 orchestrator.py --resume scan_20240101_120000

  # Compare with previous scan
  python3 orchestrator.py 10.0.0.0/16 --diff prev_results.csv

  # Distributed scanning — server 2 of 4
  python3 orchestrator.py 10.0.0.0/8 --shard 2/4

  # Dry run — show plan without scanning
  python3 orchestrator.py 10.0.0.0/16 --dry-run
""")

    # Target
    ap.add_argument("targets", nargs="*", default=[],
                    help="Target ranges (CIDR, range, or single IP)")
    ap.add_argument("-f", "--file", help="File with target ranges")
    ap.add_argument("-e", "--exclude", nargs="*", default=[],
                    help="Exclude ranges / IPs (فیکس v3: تک-IP هم کار می‌کند)")

    # Ports
    ap.add_argument("-p", "--ports", default=DEFAULT_PORTS,
                    help=f"Ports to scan (default: {DEFAULT_PORTS})")

    # Phase 1: L4
    ap.add_argument("--l4-engine", choices=["masscan", "naabu", "auto"], default="masscan",
                    help="L4 engine (default: masscan)")
    ap.add_argument("--masscan-rate", type=int, default=5000,
                    help="Masscan packets/sec (default: 5000)")
    ap.add_argument("--masscan-path", default="masscan", help="Path to masscan binary")
    ap.add_argument("--naabu-path", default="naabu", help="Path to naabu binary")
    ap.add_argument("--masscan-config",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "configs", "masscan_stealth.conf"),
                    help="Masscan config file (validated with --echo preflight)")
    ap.add_argument("--interface", help="Network interface for masscan")
    ap.add_argument("--phase1-input", help="Skip Phase 1 — load open ports from this file")
    ap.add_argument("--masscan-wait", type=int, default=5,
                    help="Masscan response wait seconds (default: 5)")
    ap.add_argument("--masscan-retries", type=int, default=2,
                    help="Masscan retries (default: 2)")
    ap.add_argument("--shard", help="Shard as i/n (e.g. 2/4) for distributed scanning")

    # Phase 2: L7 Prober
    ap.add_argument("--engine", choices=["go", "httpx", "auto"], default="auto",
                    help="L7 engine: go (compiled), httpx (installed), auto (detect)")
    ap.add_argument("--prober-bin",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "go_prober", "prober"),
                    help="Path to Go prober binary")
    ap.add_argument("--concurrency", type=int, default=200,
                    help="L7 concurrent workers (default: 200)")
    ap.add_argument("--l7-rate", type=int, default=500,
                    help="L7 max requests/sec (default: 500)")
    ap.add_argument("--timeout", type=int, default=8,
                    help="L7 request timeout in seconds (default: 8)")
    ap.add_argument("--jitter", type=int, default=20, help="Jitter 0-N ms (default: 20)")
    ap.add_argument("--think-time", type=int, default=50,
                    help="Browser think time 0-N ms (default: 50)")
    ap.add_argument("--browser", default="random",
                    choices=["chrome", "firefox", "edge", "random"],
                    help="Browser profile for TLS fingerprint")
    ap.add_argument("--max-redirects", type=int, default=3,
                    help="Max redirect hops (default: 3)")
    ap.add_argument("--no-favicon", action="store_true",
                    help="Disable favicon fetch + hash")
    ap.add_argument("--favicon-db",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "configs", "favicon_db.json"),
                    help="Favicon hash DB (JSON)")
    ap.add_argument("--no-adaptive", action="store_true",
                    help="Disable adaptive rate (circuit breaker)")
    ap.add_argument("--no-retry", action="store_true",
                    help="Disable second retry pass")

    # Proxy & Source IP
    ap.add_argument("--proxy", help="Proxy file (one per line)")
    ap.add_argument("--source-ips", help="Source IP file for rotation")

    # Output & features
    ap.add_argument("-o", "--out",
                    default=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    help="Output prefix")
    ap.add_argument("--resume", help="Resume from previous scan (output prefix) — "
                                     "skips already-found web services")
    ap.add_argument("--diff", help="CSV of a previous scan — report new/removed/changed")
    ap.add_argument("--rdns", action="store_true",
                    help="Resolve PTR records for found web IPs (hostname column)")
    ap.add_argument("--no-html", action="store_true", help="Disable HTML report")
    ap.add_argument("--notify-token", help="Telegram bot token (optional)")
    ap.add_argument("--notify-chat", help="Telegram chat id (optional)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print the plan (commands, estimates) without scanning")

    args = ap.parse_args()

    global LOCAL_IPS
    LOCAL_IPS = detect_local_ips()

    t_start = time.monotonic()
    log("=" * 60)
    log(f"  Stealth Asset Scanner v{VERSION}")
    log(f"  Architecture: L4 (masscan/naabu) + L7 (Go Prober v3)")
    log("=" * 60)

    # ── Shard parsing ──
    shard, shards = None, 1
    if args.shard:
        try:
            parts = args.shard.split('/')
            shard, shards = int(parts[0]), int(parts[1])
            assert 1 <= shard <= shards and shards > 1
            log(f"[shard] This host scans shard {shard}/{shards}")
        except Exception:
            log("[!] invalid --shard format (expected i/n)")
            sys.exit(2)

    # ── Check prerequisites ──
    has_prober = os.path.isfile(args.prober_bin) and os.access(args.prober_bin, os.X_OK)
    has_httpx = check_tool("httpx", "httpx")

    engine = args.engine
    if engine == "auto":
        if has_prober:
            engine = "go"
            log(f"[engine] Go prober detected: {args.prober_bin}")
        elif has_httpx:
            engine = "httpx"
            log("[engine] httpx detected")
        else:
            engine = "go"
            log(f"[engine] No L7 engine found — will try Go prober at: {args.prober_bin}")
            log(f"[engine] Build: cd go_prober && go mod tidy && go build -o {args.prober_bin} .")
    log(f"[engine] Using: {engine}")

    # ── Load targets ──
    targets = list(args.targets)
    if args.file:
        with open(args.file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)

    if not targets and not args.phase1_input and not args.resume:
        ap.error("No targets specified. Use --phase1-input / --resume.")

    # ── Output paths ──
    prefix = args.out
    p1_file = f"{prefix}_masscan.txt"
    p2_jsonl = f"{prefix}_prober.jsonl"
    csv_file = f"{prefix}_results.csv"
    summary_file = f"{prefix}_summary.txt"
    diff_file = f"{prefix}_diff.txt"
    html_file = f"{prefix}_report.html"

    # ════════════════════════════════════════════════════════════
    # PHASE 1: Port Discovery
    # ════════════════════════════════════════════════════════════

    open_ports = []
    resume_done = set()

    if args.resume:
        # فیکس v3: --resume واقعاً کار می‌کند
        prev_jsonl = f"{args.resume}_prober.jsonl"
        prev_p1 = f"{args.resume}_masscan.txt"
        if os.path.exists(prev_jsonl):
            for r in load_jsonl_rows(prev_jsonl):
                if r.get('scheme') and not r.get('error'):
                    resume_done.add((str(r.get('ip')), int(r.get('port') or 0)))
            log(f"[resume] {len(resume_done):,} web services already found — will be skipped")
        if os.path.exists(prev_p1):
            open_ports = load_open_ports(prev_p1)
            log(f"[resume] loaded {len(open_ports):,} open ports from {prev_p1}")
            if not open_ports:
                sys.exit(2)
        elif not args.phase1_input:
            log(f"[resume] no masscan output at {prev_p1} — run with targets to rescan")

    if not open_ports:
        if args.phase1_input:
            log(f"[Phase 1] Skipping — loading from {args.phase1_input}")
            open_ports = load_open_ports(args.phase1_input)
            log(f"[Phase 1] Loaded {len(open_ports):,} open ports")
        else:
            cidrs, excl = expand_target_ranges(targets, args.exclude)
            if not cidrs:
                log("[!] No valid target ranges")
                sys.exit(2)

            total_ips = count_ips_in_ranges(cidrs)
            n_ports = len(args.ports.split(','))
            total_probes = total_ips * n_ports
            est_sec = total_probes / args.masscan_rate if args.masscan_rate > 0 else 0
            log(f"[Phase 1] {total_ips:,} IPs in {len(cidrs)} CIDR blocks | {n_ports} ports")
            log(f"[Phase 1] Estimated {total_probes:,} probes -> {fmt_dur(est_sec)} at {args.masscan_rate:,} pps")
            if excl:
                log(f"[Phase 1] Excluding {len(excl)} ranges")

            # preflight کانفیگ masscan (فاز ۱)
            masscan_cfg = args.masscan_config
            if args.l4_engine in ("masscan", "auto"):
                ok, msg = validate_masscan_conf(args.masscan_path, masscan_cfg)
                if ok:
                    log(f"[Phase 1] masscan config OK: {masscan_cfg}")
                else:
                    log(f"[!] masscan config INVALID ({msg}) — running without config file")
                    masscan_cfg = None

            l4 = args.l4_engine
            if l4 == "auto":
                l4 = "masscan" if check_tool("masscan", args.masscan_path) else "naabu"
                log(f"[Phase 1] L4 engine (auto): {l4}")

            if args.dry_run:
                if l4 == "masscan":
                    cmd = build_masscan_cmd(cidrs, args.ports, args.masscan_rate, excl,
                                            p1_file, config_file=masscan_cfg,
                                            interface=args.interface,
                                            wait=args.masscan_wait,
                                            retries=args.masscan_retries,
                                            shard=shard, shards=shards)
                else:
                    cmd = [args.naabu_path, "-l", "<ranges.txt>", "-p", args.ports,
                           "-rate", str(args.masscan_rate), "-json", "-silent"]
                log("")
                log("[dry-run] Phase 1 command:")
                log("  " + " ".join(cmd))
                log(f"[dry-run] Phase 2: prober over open ports (concurrency={args.concurrency}, "
                    f"rate={args.l7_rate}, adaptive={not args.no_adaptive}, retry={not args.no_retry})")
                log(f"[dry-run] Outputs: {p1_file} | {p2_jsonl} | {csv_file} | {summary_file}"
                    + (" | " + html_file if not args.no_html else ""))
                log(f"[dry-run] Estimated Phase-1 time: {fmt_dur(est_sec)}")
                log("[dry-run] Nothing was scanned.")
                sys.exit(0)

            if l4 == "masscan":
                if not check_tool("masscan", args.masscan_path):
                    log("[!] masscan not found!")
                    log("    Install: apt install masscan (Debian/Ubuntu)")
                    log("    Alternative: --l4-engine naabu")
                    sys.exit(2)
                open_ports = run_masscan(
                    cidrs=cidrs, ports=args.ports, rate=args.masscan_rate,
                    exclude=excl, output_file=p1_file, masscan_path=args.masscan_path,
                    config_file=masscan_cfg, interface=args.interface,
                    wait=args.masscan_wait, retries=args.masscan_retries,
                    shard=shard, shards=shards)
            else:
                open_ports = run_naabu(cidrs, args.ports, args.masscan_rate, excl,
                                       p1_file, naabu_path=args.naabu_path,
                                       shard=shard, shards=shards)

            if not open_ports:
                log("[!] No open ports found in Phase 1")
                sys.exit(0)

    # حذف تارگت‌هایی که در اسکن قبلی موفق بوده‌اند (resume)
    if resume_done:
        before = len(open_ports)
        open_ports = [(ip, p) for (ip, p) in open_ports if (ip, p) not in resume_done]
        log(f"[resume] {before - len(open_ports):,} targets skipped, {len(open_ports):,} remaining")

    if not open_ports:
        log("[!] Nothing left to probe")
        sys.exit(0)

    # ════════════════════════════════════════════════════════════
    # PHASE 2: HTTP Probing
    # ════════════════════════════════════════════════════════════

    l7_cfg = {
        'concurrency': args.concurrency,
        'rate': args.l7_rate,
        'timeout': args.timeout * 1000,  # ms برای Go prober
        'jitter': args.jitter,
        'think_time': args.think_time,
        'browser': args.browser,
        'max_body': 131072,
        'max_redirects': args.max_redirects,
        'favicon': not args.no_favicon,
        'favicon_db': args.favicon_db,
        'adaptive': not args.no_adaptive,
        'retry': not args.no_retry,
        'shard': shard or 1,
        'shards': shards,
    }

    proxy_file_for_prober = None
    if args.proxy and HAS_PROXY_POOL:
        pool = ProxyPool()
        pool.load_from_file(args.proxy)
        proxy_file_for_prober = f"{prefix}_proxies_alive.txt"
        pool.export_for_go(proxy_file_for_prober)
        l7_cfg['proxy_file'] = proxy_file_for_prober
    elif args.proxy:
        l7_cfg['proxy_file'] = args.proxy

    if args.source_ips:
        l7_cfg['source_ips_file'] = args.source_ips

    log("")
    log(f"[Phase 2] {len(open_ports):,} open ports to probe")

    if engine == "go":
        run_go_prober(open_ports, args.prober_bin, p2_jsonl, l7_cfg)
    elif engine == "httpx":
        run_httpx(open_ports, p2_jsonl, l7_cfg)

    # ════════════════════════════════════════════════════════════
    # RESULT PROCESSING
    # ════════════════════════════════════════════════════════════

    if engine == "go":
        raw_rows = load_jsonl_rows(p2_jsonl)
    else:
        raw_rows = httpx_rows(p2_jsonl)

    if not raw_rows:
        log("[!] No results found")
        sys.exit(0)

    rows = dedupe_rows(raw_rows)
    log(f"[results] {len(raw_rows):,} raw -> {len(rows):,} unique (ip,port)")

    if args.rdns:
        rdns_enrich(rows)

    meta = {
        'targets': ", ".join(targets[:3]) + ("..." if len(targets) > 3 else ""),
        'engine': engine,
        'l4': args.l4_engine,
        'shard': shard, 'shards': shards,
    }
    summary_text, web_count, err_count = process_results(rows, csv_file, summary_file, meta)

    diff_counts = None
    if args.diff:
        diff_counts = diff_scans(rows, args.diff, diff_file)

    if not args.no_html:
        generate_html_report(rows, html_file, meta)

    log("")
    log(summary_text)
    if diff_counts:
        log(f"[diff] new: {diff_counts['new']:,} | removed: {diff_counts['gone']:,} "
            f"| changed: {diff_counts['changed']:,} -> {diff_file}")

    total_time = time.monotonic() - t_start
    log("")
    log(f"=== Pipeline Complete in {fmt_dur(total_time)} ===")
    log(f"    Open ports (Phase 1): {len(open_ports):,}")
    log(f"    Web services (Phase 2): {web_count:,}")
    log(f"    Results CSV: {csv_file}")
    if not args.no_html:
        log(f"    HTML report: {html_file}")
    log(f"    Summary: {summary_file}")

    if args.notify_token and args.notify_chat:
        msg = (f" Stealth Scan Finished\n"
               f" Targets: {meta.get('targets', '-')}\n"
               f" Open ports: {len(open_ports):,}\n"
               f" Web services: {web_count:,}\n"
               f" Duration: {fmt_dur(total_time)}")
        if diff_counts:
            msg += (f"\n Diff vs previous: +{diff_counts['new']} / "
                    f"-{diff_counts['gone']} / ~{diff_counts['changed']}")
        notify_telegram(args.notify_token, args.notify_chat, msg)


if __name__ == "__main__":
    main()
