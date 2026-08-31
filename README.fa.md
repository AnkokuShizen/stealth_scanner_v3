# Stealth Asset Scanner v3.0

اسکنر کشف وب‌سرویس‌های داخلی — سریع، پنهان، کامل

معماری دو مرحله‌ای:

```
┌──────────────────────────┐      ┌───────────────────────────────┐
│  فاز ۱ — L4 Discovery    │      │  فاز ۲ — L7 Fingerprinting    │
│  Masscan / naabu (SYN)   │ ───► │  Go Prober v3 (uTLS مرورگر)   │
│  میلیون‌ها IP در ساعت     │      │  favicon hash + tech + گزارش  │
└──────────────────────────┘      └───────────────────────────────┘
```

- **فاز ۱:** پورت‌های وب باز در رنج خیلی بزرگ با SYN scan (بدون هندشیک کامل) پیدا می‌شود.
- **فاز ۲:** روی هر پورت باز، پروب HTTP با TLS fingerprint واقعی کروم/فایرفاکس/اج زده می‌شود و تایتل، تکنولوژی، هش favicon، نشت IP داخلی و... استخراج می‌شود.

---

## ⚠ مجوز

**فقط روی رنج‌هایی که مجوز رسمی اسکن داری استفاده کن.** اسکن بدون مجوز در اکثر کشورها جرم است. رنج‌های حساس (OT/ICS، تجهیزات پزشکی، Ilo/BMC سرورها) را حتماً با `--exclude` کنار بگذار.

---

## ۱. نصب و Build

### پیش‌نیازها

```bash
# Masscan (فاز ۱)
sudo apt install masscan
# یا بیلد از سورس برای نسخه جدیدتر:
git clone https://github.com/robertdavidgraham/masscan && cd masscan && make

# Go 1.22+ برای کامپایل prober
# از https://go.dev/dl نصب کن
```

### Build پروبر

```bash
cd go_prober
go mod tidy        # دانلود وابستگی‌ها (utls, brotli, zstd, murmur3)
go build -o prober .
```

اگر Go نداری، orchestrator خودش از **httpx** به عنوان fallback استفاده می‌کند:

```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### مجوزهای لازم

- Masscan و naabu برای SYN scan نیاز به **root/CAP_NET_RAW** دارند:

```bash
sudo setcap cap_net_raw+ep go_prober/prober 2>/dev/null  # prober به raw نیاز ندارد، فقط masscan
sudo python3 orchestrator.py 10.0.0.0/16
```

---

## ۲. شروع سریع

```bash
# ساده‌ترین حالت
sudo python3 orchestrator.py 10.0.0.0/16

# پورت‌ها و نرخ دلخواه
sudo python3 orchestrator.py 10.0.0.0/16 -p 80,443,8080,8443 --masscan-rate 3000

# اول dry-run بزن تا پلن اجرا را ببینی (هیچ پکتی ارسال نمی‌شود)
python3 orchestrator.py 10.0.0.0/16 --dry-run
```

خروجی‌ها (با پیش‌فرض `scan_<زمان>`):

| فایل | محتوا |
|---|---|
| `scan_*_masscan.txt` | خروجی خام فاز ۱ |
| `scan_*_prober.jsonl` | خروجی JSON خطی فاز ۲ |
| `scan_*_results.csv` | جدول نهایی (Excel) |
| `scan_*_report.html` | گزارش تعاملی HTML |
| `scan_*_summary.txt` | خلاصه متنی |
| `scan_*_diff.txt` | فقط وقتی `--diff` بدهی |

---

## ۳. سناریوهای مهم

### الف) اسکن دوره‌ای + گزارش تغییرات (Asset Drift)

```bash
# بار اول
sudo python3 orchestrator.py 10.0.0.0/16 --out scan_monday --rdns

# هفته بعد — گزارش جدید/حذف‌شده/عوض‌شده نسبت به قبل
sudo python3 orchestrator.py 10.0.0.0/16 --out scan_next --diff scan_monday_results.csv
```

### ب) ادامه‌ دادن اسکن قطع‌شده (Resume)

```bash
sudo python3 orchestrator.py --resume scan_monday
# اگر خروجی masscan موجود باشد فاز ۱ skip می‌شود و فقط تارگت‌های
# هنوز-کشف-نشده دوباره probe می‌شوند.
```

### ج) اسکن توزیع‌شده روی چند سرور (برای رنج خیلی خیلی بزرگ)

```bash
# سرور ۱ از ۴
sudo python3 orchestrator.py 10.0.0.0/8 --shard 1/4 --out s1
# سرور ۲ از ۴
sudo python3 orchestrator.py 10.0.0.0/8 --shard 2/4 --out s2
# ...
```
هم masscan (فلاگ بومی `--shard`) و هم prober (فیلتر FNV همسان) shard را رعایت می‌کنند. مزیت جانبی: هر سرور یک source IP جدا دارد و DoS policy درون‌شبکه‌ای را کمتر حساس می‌کند.

### د) پر کردن DB دستگاه‌های شناخته‌شده (favicon)

```bash
pip install mmh3
cd tools
python3 favicon_hash.py https://10.10.0.1 --add "FortiGate Login" "Network Device" --db ../configs/favicon_db.json
python3 favicon_hash.py https://10.10.0.2:8443 --add "vCenter" "Virtualization" --db ../configs/favicon_db.json
```
از این به بعد هر دستگاهی با همان favicon در خروجی + گزارش HTML، مستقیماً اسم‌گذاری می‌شود. هش‌های پرتکرارِ لیبل‌نشده هم در summary لیست می‌شوند تا label شان کنی.

### هـ) پنهان‌کاری بیشتر با پراکسی / Source IP

```bash
sudo python3 orchestrator.py 10.0.0.0/16 \
    --source-ips src_ips.txt        # چند IP روی همین سرور — rotation
# یا
sudo python3 orchestrator.py 10.0.0.0/16 \
    --proxy proxies.txt             # socks5://user:pass@host:1080 یا http://...
```

### و) اعلان تلگرام

```bash
sudo python3 orchestrator.py 10.0.0.0/16 \
    --notify-token 123456:ABC-DEF... --notify-chat -1001234567890
```

---

## ۴. تنظیمات Stealth (خلاصه)

| لایه | مکانیزم |
|---|---|
| L4 | نرخ پایین (`rate` در conf)، `--randomize-hosts`، پورت منبع تصادفی epheremal، `--wait` و `--retries` tune شده، exclude رنج حساس |
| L7 | TLS fingerprint واقعی مرورگر (uTLS)، ترتیب هدر دقیقاً مرورگر، UA پایدار per-IP، jitter + think time، رامپ‌آپ ۱۵ ثانیه‌ای نرخ، favicon روی همان اتصال keep-alive و داخل rate limiter |
| تطبیقی | Circuit breaker: بالا رفتن نرخ خطا (نشانه throttle شدن توسط WAF) → نصف شدن خودکار نرخ؛ سالم شدن → رامپ مجدد |
| پوشش | پاس دوم خودکار برای خطاهای گذرا (timeout/reset/...) با پروفایل متفاوت |

نکات مهم:

- **TTL:** stock masscan با TTL 255 می‌فرستد و قابل تغییر نیست (بدون پچ سورس). در تحلیل‌های forensic این نکته را بدان.
- **DoS policy فورتی‌گیت:** آستانه `tcp_syn_flood` معمولاً per-source-IP است؛ ۵۰۰۰pps از یک سرور تقریباً حتماً log/alert می‌دهد. اگر پنهان‌کاری کامل می‌خواهی: rate را ۵۰۰–۱۰۰۰ بگذار و از shard چند-سروری استفاده کن.
- **http2:** prober عمداً ALPN را روی `http/1.1` قفل می‌کند (سرورهای h2-only وگرنه fail می‌شدند). این یعنی هزینه کوچکی در fidelity fingerprint در ازای پوشش کامل.

---

## ۵. فلاگ‌های پرکاربرد orchestrator

```
تارگت:
  targets...               رنج‌ها (CIDR، رنج، تک-IP) — مثل 10.0.0.0/16 یا 10.0.0.1-250
  -f FILE                  فایل رنج‌ها (هر خط یکی)
  -e / --exclude           رنج/IPهای مستثنی (حالا تک-IP هم کار می‌کند)
  -p PORTS                 پورت‌های وب (پیش‌فرض: 80,443,8000,8080,8081,8443,8888,9090,10443)

فاز ۱:
  --l4-engine              masscan | naabu | auto
  --masscan-rate N         پکت بر ثانیه (پیش‌فرض ۵۰۰۰)
  --masscan-wait N         ثانیه انتظار برای پاسخ (پیش‌فرض ۵)
  --masscan-retries N      تلاش مجدد (پیش‌فرض ۲)
  --shard i/n              اسکن توزیع‌شده
  --phase1-input FILE      skip فاز ۱ و استفاده از لیست آماده
  --interface IFACE        اینترفیس شبکه

فاز ۲:
  --engine                 go | httpx | auto
  --concurrency N          ورکر موازی (پیش‌فرض ۲۰۰)
  --l7-rate N              حداکثر درخواست/ثانیه (پیش‌فرض ۵۰۰)
  --browser                chrome | firefox | edge | random
  --no-adaptive            خاموش کردن circuit breaker
  --no-retry               خاموش کردن پاس دوم
  --no-favicon             خاموش کردن favicon hash

خروجی و فیچرها:
  --out PREFIX             پیشوند فایل‌های خروجی
  --resume PREFIX          ادامه اسکن قبلی
  --diff prev.csv          گزارش تغییرات نسبت به اسکن قبل
  --rdns                   حل PTR برای IPهای دارای وب
  --no-html                بدون گزارش HTML
  --notify-token/-chat     تلگرام
  --dry-run                فقط نمایش پلن
```

فلاگ‌های prober (استفاده مستقل): `./prober -h`

---

## ۶. ساختار پروژه

```
stealth_scanner_v3/
├── orchestrator.py            ← نقطه ورود اصلی (v3.0)
├── go_prober/
│   ├── prober.go              ← سورس پروبر L7 (v3.0)
│   ├── go.mod
│   └── prober                 ← بعد از build
├── configs/
│   ├── masscan_stealth.conf   ← کانفیگ masscan (validated با --echo)
│   └── favicon_db.json        ← DB هش favicon دستگاه‌ها
├── tools/
│   └── favicon_hash.py        ← سازنده هش برای پر کردن DB
└── README.md
```

---

## ۷. جدول باگ‌های فیکس‌شده (v2 → v3)

| # | باگ | اثر در v2 | وضعیت |
|---|---|---|---|
| ۱ | پارسر خروجی `-oG` masscan | همیشه ۰ پورت کشف می‌شد — پایپ‌لاین می‌شکست | ✅ |
| ۲ | فلاگ `--excludeclip` ناموجود | masscan فوراً fatal | ✅ |
| ۳ | عدم decompress بادی gzip/br/zstd | تایتل‌های خالی روی خیلی از هاست‌ها | ✅ |
| ۴ | ALPN به h2 negotiate می‌شد | هاست‌های HTTPS سخت‌گیر fail | ✅ |
| ۵ | bufio.Reader جدید در هر hop | پاسخ خراب در redirect های keep-alive | ✅ |
| ۶ | timeout ۸۰۰۰ ثانیه در مسیر httpx | فاز ۲ هنگ می‌کرد | ✅ |
| ۷ | timeout ثابت ۲ ساعت masscan | kill وسط اسکن رنج بزرگ | ✅ timeout پویا |
| ۸ | `--resume` آرگومان مرده | resume کار نمی‌کرد | ✅ |

---

## ۸. تست سلامت بعد از Build

```bash
# ۱) syntax و help
python3 orchestrator.py --help

# ۲) کانفیگ masscan سالم است؟
sudo masscan -c configs/masscan_stealth.conf --echo

# ۳) پروبر به تنهایی روی یک سرور مشخص:
echo "10.10.0.1:443" | ./go_prober/prober -o - | python3 -m json.tool

# ۴) dry-run کامل:
python3 orchestrator.py 10.10.0.0/24 --dry-run
```
