#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
favicon_hash.py — ساخت هش favicon در فرمت شودان (mmh3 روی base64 با
خط‌شکستن ۷۶ کاراکتری) برای پر کردن configs/favicon_db.json

نصب پیش‌نیاز:
    pip install mmh3

استفاده:
    # از یک URL (گواهی self-signed هم قبول است):
    python3 favicon_hash.py https://10.10.0.1
    python3 favicon_hash.py https://10.10.0.1:8443 --add "FortiGate Login" "Network Device"

    # از یک فایل محلی favicon.ico:
    python3 favicon_hash.py --file /path/to/favicon.ico

    # افزودن مستقیم به DB:
    python3 favicon_hash.py https://10.10.0.1 --add "vCenter" "Virtualization" \
        --db ../configs/favicon_db.json
"""

import argparse
import base64
import json
import ssl
import sys
import urllib.request

try:
    import mmh3
except ImportError:
    print("[!] mmh3 نصب نیست:  pip install mmh3")
    sys.exit(1)


def hash_bytes(data: bytes) -> int:
    """دقیقاً همان الگوریتم http.favicon.hash شودان"""
    return mmh3.hash(base64.encodebytes(data))


def fetch_favicon(url: str, timeout: int = 15) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = url.rstrip('/')
    if not base.startswith(('http://', 'https://')):
        base = 'https://' + base
    for candidate in (base + '/favicon.ico',):
        req = urllib.request.Request(candidate, headers={'User-Agent': 'Mozilla/5.0'})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                if r.status == 200:
                    return r.read()
        except Exception as e:
            print(f"[!] {candidate}: {e}", file=sys.stderr)
    raise SystemExit("[!] favicon دریافت نشد")


def main():
    ap = argparse.ArgumentParser(description="Shodan-style favicon hash generator")
    ap.add_argument("url", nargs="?", help="URL یا IP (بدون --file)")
    ap.add_argument("--file", help="فایل محلی favicon")
    ap.add_argument("--add", nargs=2, metavar=("NAME", "CATEGORY"),
                    help="افزودن به favicon_db.json")
    ap.add_argument("--db", default="../configs/favicon_db.json",
                    help="مسیر favicon_db.json (default: ../configs/favicon_db.json)")
    args = ap.parse_args()

    if args.file:
        with open(args.file, 'rb') as f:
            data = f.read()
    elif args.url:
        data = fetch_favicon(args.url)
    else:
        ap.error("یک URL بدهید یا --file")

    h = hash_bytes(data)
    print(f"favicon_hash = {h}")

    if args.add:
        name, category = args.add
        try:
            with open(args.db, 'r', encoding='utf-8') as f:
                db = json.load(f)
        except Exception:
            db = {}
        db[str(h)] = {"name": name, "category": category}
        with open(args.db, 'w', encoding='utf-8') as f:
            json.dump(db, f, ensure_ascii=False, indent=2)
        print(f"[+] به {args.db} اضافه شد: {h} -> {name}")
        print("[!] یادت نره کلیدهای EXAMPLE رو از DB حذف کنی.")


if __name__ == "__main__":
    main()
