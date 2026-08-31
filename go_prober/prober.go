package main

// ═══════════════════════════════════════════════════════════════════
// Stealth L7 Prober v3.0
// ============================================================
// تغییرات نسبت به v2:
//   [Phase 0 — باگ‌فیکس]
//   - decompress دستی gzip/deflate/br/zstd (قبلاً title روی بادی فشرده
//     کار می‌کرد و خالی برمی‌گشت)
//   - قفل کردن ALPN روی http/1.1 (قبلاً سرورهای h2-only fail می‌شدند)
//   - یک bufio.Reader برای کل طول اتصال (باقی‌مونده بافر بین hopهای
//     redirect دور ریخته نمی‌شود) + drain کامل بادی
//   - حذف هدر Cookie خالی (آنومالی fingerprint)
//
//   [Phase 1 — Stealth]
//   - ترتیب هدرها دقیقاً مطابق کروم/فایرفاکس واقعی
//   - UA پایدار per-IP (hash از IP → همیشه همان IP همان UA را می‌گیرد)
//   - درخواست favicon داخل rate limiter و روی همان اتصال keep-alive
//   - Circuit breaker تطبیقی: افت خودکار نرخ روی افزایش نرخ خطا
//
//   [Phase 2 — فیچرها]
//   - favicon mmh3 hash (فرمت shodan) + تطبیق با DB از appliance ها
//   - تشخیص تکنولوژی: X-Powered-By، meta generator، اسم کوکی‌ها،
//     WWW-Authenticate
//   - پاس دوم هوشمند برای خطاهای گذرا (retry)
//   - پشتیبانی shard برای اسکن توزیع‌شده از چند سرور
//
// Build:
//   cd go_prober && go mod tidy && go build -o prober .
//
// مثال:
//   ./prober -i targets.txt -o results.jsonl -c 200 -rate 500
//   ./prober -i - -format masscan -o results.jsonl --shard 2 --shards 4
// ═══════════════════════════════════════════════════════════════════

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/twmb/murmur3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

const Version = "3.0.0-stealth"

var (
	titleRe     = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	tagRe       = regexp.MustCompile(`<[^>]+>`)
	ipRe        = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	masscanRe   = regexp.MustCompile(`Discovered open port (\d+)/(?:tcp|udp) on ([\d.]+)`)
	generatorRe = regexp.MustCompile(`(?i)<meta[^>]+name\s*=\s*["']generator["'][^>]+content\s*=\s*["']([^"']{1,120})["']`)
	generatorRe2 = regexp.MustCompile(`(?i)<meta[^>]+content\s*=\s*["']([^"']{1,120})["'][^>]+name\s*=\s*["']generator["']`)
	privateNets []*net.IPNet
)

func init() {
	// RFC1918 + CGNAT + Link-Local
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"100.64.0.0/10", "169.254.0.0/16",
	} {
		_, n, _ := net.ParseCIDR(cidr)
		privateNets = append(privateNets, n)
	}
}

// ═══════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════

type Target struct {
	IP   string
	Port int
}

type ScanResult struct {
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	Scheme      string `json:"scheme"`
	StatusCode  int    `json:"status_code"`
	Title       string `json:"title"`
	Server      string `json:"server"`
	PoweredBy   string `json:"powered_by,omitempty"`
	Generator   string `json:"generator,omitempty"`
	Cookies     string `json:"cookies,omitempty"`
	WWWAuth     string `json:"www_auth,omitempty"`
	Redirects   string `json:"redirects,omitempty"`
	CertCN      string `json:"cert_cn,omitempty"`
	CertSAN     string `json:"cert_san,omitempty"`
	InternalIPs string `json:"internal_ips,omitempty"`
	FaviconHash string `json:"favicon_hash,omitempty"`
	FaviconApp  string `json:"favicon_app,omitempty"`
	ElapsedMs   int64  `json:"elapsed_ms"`
	Ts          int64  `json:"ts"`
	Error       string `json:"error,omitempty"`
}

type Config struct {
	Concurrency   int
	RateLimit     int
	Timeout       time.Duration
	JitterMs      int
	ThinkTimeMs   int
	ProxyFile     string
	SourceIPsFile string
	Browser       string
	MaxBody       int
	MaxRedirects  int
	FaviconHash   bool
	FaviconDB     string
	Adaptive      bool
	Retry         bool
	Shard         int
	Shards        int
	InputFile     string
	OutputFile    string
	InputFormat   string // "plain", "masscan"
}

// ═══════════════════════════════════════════════════════════════════
// Browser Profiles — realistic TLS + HTTP fingerprints
// ═══════════════════════════════════════════════════════════════════

type BrowserProfile struct {
	UA         string
	SecChUa    string
	SecPlat    string
	AcceptLang string
	UTLSID    utls.ClientHelloID
	IsFirefox bool
}

var chromeProfiles = []BrowserProfile{
	{
		UA:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		SecChUa:    `"Chromium";v="126", "Google Chrome";v="126", "Not.A/Brand";v="99"`,
		SecPlat:    `"Windows"`,
		AcceptLang: "en-US,en;q=0.9",
		UTLSID:    utls.HelloChrome_120,
	},
	{
		UA:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		SecChUa:    `"Chromium";v="125", "Google Chrome";v="125", "Not.A/Brand";v="24"`,
		SecPlat:    `"Windows"`,
		AcceptLang: "en-US,en;q=0.9,fa;q=0.8",
		UTLSID:    utls.HelloChrome_120,
	},
	{
		UA:         "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		SecChUa:    `"Chromium";v="126", "Google Chrome";v="126", "Not.A/Brand";v="99"`,
		SecPlat:    `"Linux"`,
		AcceptLang: "en-US,en;q=0.9",
		UTLSID:    utls.HelloChrome_120,
	},
	{
		UA:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		SecChUa:    `"Chromium";v="126", "Google Chrome";v="126", "Not.A/Brand";v="99"`,
		SecPlat:    `"macOS"`,
		AcceptLang: "en-US,en;q=0.9",
		UTLSID:    utls.HelloChrome_120,
	},
}

var firefoxProfiles = []BrowserProfile{
	{
		UA:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
		AcceptLang: "en-US,en;q=0.5",
		UTLSID:    utls.HelloFirefox_120,
		IsFirefox: true,
	},
	{
		UA:         "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
		AcceptLang: "en-US,en;q=0.9,de;q=0.8",
		UTLSID:    utls.HelloFirefox_120,
		IsFirefox: true,
	},
	{
		UA:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
		AcceptLang: "en-US,en;q=0.9",
		UTLSID:    utls.HelloFirefox_120,
		IsFirefox: true,
	},
}

var edgeProfiles = []BrowserProfile{
	{
		UA:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
		SecChUa:    `"Chromium";v="126", "Microsoft Edge";v="126", "Not.A/Brand";v="99"`,
		SecPlat:    `"Windows"`,
		AcceptLang: "en-US,en;q=0.9",
		UTLSID:    utls.HelloChrome_120, // Edge از TLS کروم استفاده می‌کند
	},
}

// profileForIP — پروفایل پایدار بر اساس hash خود IP؛
// نتیجه: هر IP در rescanهای مختلف همیشه همان UA را می‌گیرد (رفتار سازگار)
func profileForIP(ip, browser string) *BrowserProfile {
	all := []BrowserProfile{}
	switch browser {
	case "chrome":
		all = chromeProfiles
	case "firefox":
		all = firefoxProfiles
	case "edge":
		all = edgeProfiles
	default: // "random" — ترکیب همه
		all = append(all, chromeProfiles...)
		all = append(all, firefoxProfiles...)
		all = append(all, edgeProfiles...)
	}
	return &all[fnv32a(ip)%uint32(len(all))]
}

func fnv32a(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

// ═══════════════════════════════════════════════════════════════════
// Proxy Rotation
// ═══════════════════════════════════════════════════════════════════

type ProxyRotator struct {
	proxies []string
	failCnt map[string]int64
	mu      sync.Mutex
	idx     uint64
}

func NewProxyRotator(file string) (*ProxyRotator, error) {
	pr := &ProxyRotator{failCnt: make(map[string]int64)}
	if file == "" {
		return pr, nil
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pr.proxies = append(pr.proxies, line)
	}
	log.Printf("[proxy] loaded %d proxies", len(pr.proxies))
	return pr, nil
}

func (pr *ProxyRotator) Next() string {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	n := len(pr.proxies)
	if n == 0 {
		return ""
	}
	for i := 0; i < n; i++ {
		candidate := pr.proxies[pr.idx%uint64(n)]
		pr.idx++
		if pr.failCnt[candidate] < 10 {
			return candidate
		}
	}
	// همه پراکسی‌ها fail شده‌اند — ریست و رندوم
	for k := range pr.failCnt {
		pr.failCnt[k] = 0
	}
	return pr.proxies[rand.Intn(n)]
}

func (pr *ProxyRotator) ReportFailure(proxyAddr string) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.failCnt[proxyAddr]++
}

// ═══════════════════════════════════════════════════════════════════
// Source IP Rotation
// ═══════════════════════════════════════════════════════════════════

type SourceIPRotator struct {
	ips []net.IP
	idx uint64
}

func NewSourceIPRotator(file string) (*SourceIPRotator, error) {
	sr := &SourceIPRotator{}
	if file == "" {
		return sr, nil
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := net.ParseIP(line)
		if ip != nil && ip.To4() != nil {
			sr.ips = append(sr.ips, ip)
		}
	}
	if len(sr.ips) > 0 {
		log.Printf("[source] loaded %d source IPs", len(sr.ips))
	}
	return sr, nil
}

func (sr *SourceIPRotator) Next() net.IP {
	if len(sr.ips) == 0 {
		return nil
	}
	return sr.ips[sr.idx%uint64(len(sr.ips))]
}

// ═══════════════════════════════════════════════════════════════════
// Token Bucket — rate limiter با ramp-up تدریجی + Scale پویا
// ═══════════════════════════════════════════════════════════════════

type TokenBucket struct {
	baseRate  float64
	baseCap   float64
	rate      float64
	capacity  float64
	tokens    float64
	factor    float64 // ضریب تطبیقی 0.125 تا 1.0
	mu        sync.Mutex
	last      time.Time
	rampStart time.Time
	rampDur   time.Duration
}

func NewTokenBucket(rate int, burst int, rampDur time.Duration) *TokenBucket {
	tb := &TokenBucket{
		baseRate:  float64(rate),
		baseCap:   float64(burst),
		tokens:    1.0, // شروع از ۱ برای ramp-up تدریجی
		factor:    1.0,
		last:      time.Now(),
		rampStart: time.Now(),
		rampDur:   rampDur,
	}
	if burst <= 0 {
		tb.baseCap = float64(rate)
	}
	tb.rate = tb.baseRate
	tb.capacity = tb.baseCap
	return tb
}

// Scale — تغییر ضریب نرخ توسط governor (circuit breaker)
func (tb *TokenBucket) Scale(f float64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.factor *= f
	if tb.factor > 1.0 {
		tb.factor = 1.0
	}
	if tb.factor < 0.125 {
		tb.factor = 0.125
	}
	tb.rate = tb.baseRate * tb.factor
	tb.capacity = tb.baseCap * tb.factor
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
}

func (tb *TokenBucket) CurrentFactor() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.factor
}

func (tb *TokenBucket) Wait(ctx context.Context) error {
	for {
		tb.mu.Lock()
		now := time.Now()
		// افزایش تدریجی ظرفیت در دوره ramp-up
		capNow := tb.capacity
		if elapsed := now.Sub(tb.rampStart); elapsed < tb.rampDur {
			frac := elapsed.Seconds() / tb.rampDur.Seconds()
			capNow = 1.0 + (tb.capacity-1.0)*frac
		}
		tb.tokens = min(capNow, tb.tokens+(now.Sub(tb.last).Seconds())*tb.rate)
		tb.last = now
		if tb.tokens >= 1.0 {
			tb.tokens -= 1.0
			tb.mu.Unlock()
			return nil
		}
		waitDur := time.Duration((1.0 - tb.tokens) / tb.rate * float64(time.Second))
		if waitDur > 50*time.Millisecond {
			waitDur = 50 * time.Millisecond
		}
		tb.mu.Unlock()
		select {
		case <-time.After(waitDur):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// ═══════════════════════════════════════════════════════════════════
// Adaptive Governor — circuit breaker روی نرخ خطا
// اگر WAF شروع به drop/throttle کند، نرخ خطا بالا می‌رود و
// governor خودش نرخ را کم می‌کند؛ وقتی شبکه سالم شد دوباره ramp می‌شود.
// ═══════════════════════════════════════════════════════════════════

type AdaptiveGovernor struct {
	enabled bool
	bucket  *TokenBucket
	mu      sync.Mutex
	total   int64
	errs    int64
}

const (
	govWindowSize = 200  // هر ۲۰۰ نتیجه یک‌بار ارزیابی
	govErrHigh    = 0.40 // بالای ۴۰٪ خطا → کاهش نرخ
	govErrLow     = 0.10 // زیر ۱۰٪ خطا → افزایش تدریجی
)

func (g *AdaptiveGovernor) Record(hadErr bool) {
	if g == nil || !g.enabled || g.bucket == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.total++
	if hadErr {
		g.errs++
	}
	if g.total >= govWindowSize {
		rate := float64(g.errs) / float64(g.total)
		switch {
		case rate > govErrHigh:
			g.bucket.Scale(0.5)
			log.Printf("[adaptive] error rate %.0f%% → rate halved (factor %.2f)",
				rate*100, g.bucket.CurrentFactor())
		case rate < govErrLow && g.bucket.CurrentFactor() < 1.0:
			g.bucket.Scale(1.25)
			log.Printf("[adaptive] error rate %.0f%% → rate ramping up (factor %.2f)",
				rate*100, g.bucket.CurrentFactor())
		}
		g.total, g.errs = 0, 0
	}
}

// ═══════════════════════════════════════════════════════════════════
// Proxy Dialers
// ═══════════════════════════════════════════════════════════════════

// bufferedConn اتصال را با bufio.Reader می‌پیچد تا بایت‌های خوانده‌شده
// از پاسخ CONNECT پراکسی گم نشوند.
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (bc *bufferedConn) Read(b []byte) (int, error) {
	return bc.br.Read(b)
}

func dialViaHTTPProxy(proxyURL, targetAddr string, timeout time.Duration) (net.Conn, error) {
	pu, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", pu.Host, timeout)
	if err != nil {
		return nil, err
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
	if pu.User != nil {
		auth := base64.StdEncoding.EncodeToString([]byte(pu.User.String()))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	connectReq += "\r\n"

	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy write: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT returned %d", resp.StatusCode)
	}

	return &bufferedConn{Conn: conn, br: br}, nil
}

func dialViaSOCKS5(proxyURL, targetAddr string, timeout time.Duration) (net.Conn, error) {
	pu, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	dialer, err := proxy.FromURL(pu, proxy.Direct)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", targetAddr)
}

func dialWithProxy(proxyURL, targetAddr string, timeout time.Duration) (net.Conn, error) {
	if proxyURL == "" {
		return net.DialTimeout("tcp", targetAddr, timeout)
	}
	pu, _ := url.Parse(proxyURL)
	scheme := strings.ToLower(pu.Scheme)
	switch scheme {
	case "socks5", "socks5h":
		return dialViaSOCKS5(proxyURL, targetAddr, timeout)
	case "http", "https":
		return dialViaHTTPProxy(proxyURL, targetAddr, timeout)
	default:
		return net.DialTimeout("tcp", targetAddr, timeout)
	}
}
// ═══════════════════════════════════════════════════════════════════
// Favicon DB — mmh3 hash در فرمت shodan + تطبیق با applianceهای شناخته‌شده
// ═══════════════════════════════════════════════════════════════════

type FaviconEntry struct {
	Name     string `json:"name"`
	Category string `json:"category"`
}

var faviconDB map[string]FaviconEntry

func loadFaviconDB(path string) {
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[!] favicon db: %v", err)
		return
	}
	db := make(map[string]FaviconEntry)
	if err := json.Unmarshal(data, &db); err != nil {
		log.Printf("[!] favicon db parse: %v", err)
		return
	}
	// فقط کلیدهای عددی (هش) را بپذیر — کلیدهای توضیحی مثل _README نادیده گرفته می‌شوند
	faviconDB = make(map[string]FaviconEntry)
	for k, v := range db {
		if _, err := strconv.ParseInt(k, 10, 64); err == nil {
			faviconDB[k] = v
		}
	}
	log.Printf("[favicon] loaded %d known appliance hashes from %s", len(faviconDB), path)
}

// shodanFaviconHash — mmh3 روی base64 با خط‌شکستن ۷۶ کاراکتری
// (دقیقاً همان الگوریتم http.favicon.hash شودان)
func shodanFaviconHash(body []byte) string {
	b64 := base64.StdEncoding.EncodeToString(body)
	var sb strings.Builder
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end])
		sb.WriteByte('\n')
	}
	h := murmur3.Sum32([]byte(sb.String()))
	return strconv.FormatInt(int64(int32(h)), 10) // signed 32-bit مثل mmh3 پایتون
}

// ═══════════════════════════════════════════════════════════════════
// Body Decompression — فیکس بحرانی v2
// http.ReadResponse برخلاف http.Transport هیچ decompress ای انجام
// نمی‌دهد؛ بدون این تابع، تایتلِ بادی‌های فشرده خالی برمی‌گشت.
// ═══════════════════════════════════════════════════════════════════

const maxDecodedBody = 4 << 20 // سقف ۴MB برای جلوگیری از decompression bomb

func decodeBody(raw []byte, contentEncoding string) []byte {
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	if enc == "" || enc == "identity" {
		return raw
	}
	var r io.Reader
	switch {
	case strings.Contains(enc, "zstd"):
		zr, err := zstd.NewReader(bytes.NewReader(raw))
		if err != nil {
			return raw
		}
		defer zr.Close()
		r = io.LimitReader(zr, maxDecodedBody)
	case strings.Contains(enc, "br"):
		r = io.LimitReader(brotli.NewReader(bytes.NewReader(raw)), maxDecodedBody)
	case strings.Contains(enc, "gzip"):
		gz, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return raw
		}
		defer gz.Close()
		r = io.LimitReader(gz, maxDecodedBody)
	case strings.Contains(enc, "deflate"):
		r = io.LimitReader(flate.NewReader(bytes.NewReader(raw)), maxDecodedBody)
	default:
		return raw
	}
	out, err := io.ReadAll(r)
	if err != nil && len(out) == 0 {
		return raw
	}
	return out
}

// ═══════════════════════════════════════════════════════════════════
// Target Loader — با فیلتر shard
// ═══════════════════════════════════════════════════════════════════

func loadTargets(cfg *Config) (<-chan Target, error) {
	ch := make(chan Target, 10000)
	go func() {
		defer close(ch)
		var f *os.File
		var err error

		if cfg.InputFile == "" || cfg.InputFile == "-" {
			f = os.Stdin
		} else {
			f, err = os.Open(cfg.InputFile)
			if err != nil {
				log.Printf("[!] cannot open input: %v", err)
				return
			}
			defer f.Close()
		}

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		count := 0
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			var ip string
			var port int

			if cfg.InputFormat == "masscan" {
				m := masscanRe.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				fmt.Sscanf(m[1], "%d", &port)
				ip = m[2]
			} else {
				// Plain format: "ip:port" یا "ip,port" یا خروجی کنسول masscan
				if strings.Contains(line, ":") {
					parts := strings.SplitN(line, ":", 2)
					ip = parts[0]
					fmt.Sscanf(parts[1], "%d", &port)
				} else if strings.Contains(line, ",") {
					parts := strings.SplitN(line, ",", 2)
					ip = parts[0]
					fmt.Sscanf(parts[1], "%d", &port)
				} else if m := masscanRe.FindStringSubmatch(line); m != nil {
					fmt.Sscanf(m[1], "%d", &port)
					ip = m[2]
				} else {
					continue
				}
			}

			if ip == "" || port <= 0 || port > 65535 {
				continue
			}

			// فیلتر shard — همان الگوریتم FNV-1a در orchestrator پایتونی
			if cfg.Shards > 1 {
				key := fmt.Sprintf("%s:%d", ip, port)
				if fnv32a(key)%uint32(cfg.Shards) != uint32(cfg.Shard-1) {
					continue
				}
			}

			ch <- Target{IP: ip, Port: port}
			count++
		}
		log.Printf("[targets] loaded %d targets (shard %d/%d)", count, cfg.Shard, cfg.Shards)
	}()
	return ch, nil
}

// ═══════════════════════════════════════════════════════════════════
// HTTP Request Builder — ترتیب هدرها مطابق مرورگر واقعی
// ═══════════════════════════════════════════════════════════════════

// ترتیب هدرهای کروم واقعی در درخواست navigation (HTTP/1.1):
// Host, Connection, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform,
// Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site,
// Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding,
// Accept-Language
//
// فایرفاکس: Host, User-Agent, Accept, Accept-Language,
// Accept-Encoding, Connection, Upgrade-Insecure-Requests, Sec-Fetch-*
//
// نکته: هدر Cookie خالی حذف شد — کروم در بازدید اول هیچ Cookie نمی‌فرستد.
func buildHTTPRequest(host string, port int, path string, profile *BrowserProfile, isRedirect bool) string {
	hostHdr := host
	if port != 80 && port != 443 {
		hostHdr = fmt.Sprintf("%s:%d", host, port)
	}
	accept := "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	acceptEnc := "gzip, deflate, br, zstd"
	fetchSite := "none"
	if isRedirect {
		fetchSite = "same-origin"
	}

	var lines []string
	lines = append(lines,
		fmt.Sprintf("GET %s HTTP/1.1", path),
		fmt.Sprintf("Host: %s", hostHdr),
	)

	if profile.IsFirefox {
		lines = append(lines,
			fmt.Sprintf("User-Agent: %s", profile.UA),
			"Accept: "+accept,
			fmt.Sprintf("Accept-Language: %s", profile.AcceptLang),
			"Accept-Encoding: "+acceptEnc,
			"Connection: keep-alive",
			"Upgrade-Insecure-Requests: 1",
			"Sec-Fetch-Dest: document",
			"Sec-Fetch-Mode: navigate",
			"Sec-Fetch-Site: "+fetchSite,
			"Sec-Fetch-User: ?1",
		)
	} else {
		lines = append(lines,
			"Connection: keep-alive",
			fmt.Sprintf("sec-ch-ua: %s", profile.SecChUa),
			"sec-ch-ua-mobile: ?0",
			fmt.Sprintf("sec-ch-ua-platform: %s", profile.SecPlat),
			"Upgrade-Insecure-Requests: 1",
			fmt.Sprintf("User-Agent: %s", profile.UA),
			"Accept: "+accept,
			"Sec-Fetch-Site: "+fetchSite,
			"Sec-Fetch-Mode: navigate",
			"Sec-Fetch-User: ?1",
			"Sec-Fetch-Dest: document",
			"Accept-Encoding: "+acceptEnc,
			fmt.Sprintf("Accept-Language: %s", profile.AcceptLang),
		)
	}
	return strings.Join(lines, "\r\n") + "\r\n\r\n"
}

// درخواست favicon — شبیه fetch تصویر از صفحه باز شده
// Accept-Encoding عمداً ارسال نمی‌شود تا هش روی بایت‌های خام favicon
// (سازگار با DBهای شودان) محاسبه شود.
func buildFaviconRequest(host string, port int, scheme string, profile *BrowserProfile) string {
	hostHdr := host
	if port != 80 && port != 443 {
		hostHdr = fmt.Sprintf("%s:%d", host, port)
	}
	var lines []string
	lines = append(lines,
		"GET /favicon.ico HTTP/1.1",
		fmt.Sprintf("Host: %s", hostHdr),
	)
	if profile.IsFirefox {
		lines = append(lines,
			fmt.Sprintf("User-Agent: %s", profile.UA),
			"Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5",
			fmt.Sprintf("Accept-Language: %s", profile.AcceptLang),
			"Connection: keep-alive",
			"Sec-Fetch-Dest: image",
			"Sec-Fetch-Mode: no-cors",
			"Sec-Fetch-Site: same-origin",
		)
	} else {
		lines = append(lines,
			"Connection: keep-alive",
			fmt.Sprintf("sec-ch-ua: %s", profile.SecChUa),
			"sec-ch-ua-mobile: ?0",
			fmt.Sprintf("sec-ch-ua-platform: %s", profile.SecPlat),
			fmt.Sprintf("User-Agent: %s", profile.UA),
			"Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
			"Sec-Fetch-Site: same-origin",
			"Sec-Fetch-Mode: no-cors",
			"Sec-Fetch-Dest: image",
			fmt.Sprintf("Referer: %s://%s/", scheme, hostHdr),
			fmt.Sprintf("Accept-Language: %s", profile.AcceptLang),
		)
	}
	return strings.Join(lines, "\r\n") + "\r\n\r\n"
}

// ═══════════════════════════════════════════════════════════════════
// Response Parsing
// ═══════════════════════════════════════════════════════════════════

func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	t := tagRe.ReplaceAllString(m[1], " ")
	t = strings.TrimSpace(t)
	if len(t) > 200 {
		t = t[:200]
	}
	return t
}

func extractGenerator(body string) string {
	if m := generatorRe.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	if m := generatorRe2.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

func extractCookieNames(resp *http.Response) string {
	var names []string
	seen := make(map[string]bool)
	for _, ck := range resp.Cookies() {
		if ck != nil && ck.Name != "" && !seen[ck.Name] {
			seen[ck.Name] = true
			names = append(names, ck.Name)
		}
		if len(names) >= 6 {
			break
		}
	}
	return strings.Join(names, ",")
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	for _, n := range privateNets {
		if n.Contains(ip4) {
			return true
		}
	}
	return false
}

func findInternalIPs(text string, excludeIP string) string {
	matches := ipRe.FindAllString(text, -1)
	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		if seen[m] {
			continue
		}
		seen[m] = true
		if m == excludeIP {
			continue
		}
		if isPrivateIP(m) {
			result = append(result, m)
		}
	}
	return strings.Join(result, ", ")
}

func extractCertInfo(state *tls.ConnectionState) (cn, san string) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return "", ""
	}
	cert := state.PeerCertificates[0]
	if cert.Subject != nil {
		cn = cert.Subject.CommonName
	}
	names := cert.DNSNames
	if len(names) > 5 {
		names = names[:5]
	}
	san = strings.Join(names, ", ")
	return cn, san
}

func dedupeJoin(items []string) string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range items {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return strings.Join(out, ", ")
}

func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

// classifyConnErr — دسته‌بندی خطا برای retry هوشمند
func classifyConnErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "timeout") || strings.Contains(s, "Timed out"):
		return "timeout"
	case strings.Contains(s, "connection refused"):
		return "refused"
	case strings.Contains(s, "no route") || strings.Contains(s, "unreachable") || strings.Contains(s, "network is down"):
		return "unreachable"
	case strings.Contains(s, "TLS") || strings.Contains(s, "tls:") || strings.Contains(s, "handshake"):
		return "tls_fail"
	case strings.Contains(s, "reset"):
		return "reset"
	case s == "bad_reply":
		return "bad_reply"
	}
	return "conn_fail"
}

func isTransientError(err string) bool {
	switch err {
	case "timeout", "refused", "conn_fail", "tls_fail", "reset", "bad_reply":
		return true
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════
// Core Probe — یک scheme برای یک تارگت
// ═══════════════════════════════════════════════════════════════════

var tlsPorts = map[int]bool{443: true, 8443: true, 10443: true}

func probeScheme(ctx context.Context, target Target, scheme string, cfg *Config,
	profile *BrowserProfile, proxyAddr string, bucket *TokenBucket, srcIP net.IP) (*ScanResult, error) {

	isTLS := scheme == "https"
	addr := fmt.Sprintf("%s:%d", target.IP, target.Port)
	// timeout با ±۱۵٪ jitter
	timeout := time.Duration(float64(cfg.Timeout) * (0.85 + 0.30*rand.Float64()))

	// ── گام ۱: TCP Connect (شاید از طریق پراکسی) ──
	var rawConn net.Conn
	var err error
	if proxyAddr != "" {
		rawConn, err = dialWithProxy(proxyAddr, addr, timeout)
	} else if srcIP != nil {
		dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: srcIP, Port: 0}, Timeout: timeout}
		rawConn, err = dialer.DialContext(ctx, "tcp", addr)
	} else {
		dialer := &net.Dialer{Timeout: timeout}
		rawConn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}

	conn := net.Conn(rawConn)
	defer conn.Close()

	// ── گام ۲: TLS handshake با fingerprint مرورگر ──
	// NextProtos روی http/1.1 قفل می‌شود تا سرورهای h2-only نتوانند
	// ALPN را روی h2 negotiate کنند (باگ v2).
	var tlsState *tls.ConnectionState
	if isTLS {
		sni := ""
		if !isIPAddress(target.IP) {
			sni = target.IP
		}
		utlsConn := utls.UClient(rawConn, &utls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		}, profile.UTLSID)

		if err := utlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		cs := utlsConn.ConnectionState()
		tlsState = &cs
		conn = utlsConn
	}

	// ── گام ۳: درخواست‌ها با keep-alive روی یک اتصال ──
	// bufio.Reader یک‌بار ساخته می‌شود (فیکس باگ redirect در v2)
	br := bufio.NewReaderSize(conn, 65536)
	conn.SetDeadline(time.Now().Add(timeout))

	var leakedIPs []string
	var allRedirects []string
	var bestResult *ScanResult
	connDirty := false // اگر بادی کامل drain نشود اتصال قابل استفاده مجدد نیست

	currentPath := "/"
	isRedirectHop := false

	for hop := 0; hop <= cfg.MaxRedirects; hop++ {
		if ctx.Err() != nil {
			break
		}
		reqStr := buildHTTPRequest(target.IP, target.Port, currentPath, profile, isRedirectHop)
		if _, err := conn.Write([]byte(reqStr)); err != nil {
			connDirty = true
			break
		}

		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			connDirty = true
			break
		}

		rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, int64(cfg.MaxBody)))
		// drain باقیمانده بادی تا keep-alive سالم بماند
		if _, derr := io.CopyN(io.Discard, resp.Body, 1<<20); derr == nil {
			connDirty = true // هنوز داده مانده — اتصال آلوده است
		}
		resp.Body.Close()
		bodyStr := string(decodeBody(rawBody, resp.Header.Get("Content-Encoding")))

		// نشت IP داخلی در هدرها + بادی
		var hdrDump strings.Builder
		for k, vv := range resp.Header {
			for _, v := range vv {
				hdrDump.WriteString(k + ": " + v + "\n")
			}
		}
		fullText := hdrDump.String() + bodyStr
		if l := findInternalIPs(fullText, target.IP); l != "" {
			leakedIPs = append(leakedIPs, strings.Split(l, ", ")...)
		}

		bestResult = &ScanResult{
			IP:         target.IP,
			Port:       target.Port,
			Scheme:     scheme,
			StatusCode: resp.StatusCode,
			Title:      extractTitle(bodyStr),
			Server:     resp.Header.Get("Server"),
			PoweredBy:  resp.Header.Get("X-Powered-By"),
			Generator:  extractGenerator(bodyStr),
			Cookies:    extractCookieNames(resp),
			Ts:         time.Now().Unix(),
		}
		if wa := resp.Header.Get("WWW-Authenticate"); wa != "" {
			bestResult.WWWAuth = wa
		}

		// هندل redirect
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location == "" {
				break
			}
			if l := findInternalIPs(location, target.IP); l != "" {
				leakedIPs = append(leakedIPs, strings.Split(l, ", ")...)
			}
			allRedirects = append(allRedirects, location)
			if u, perr := url.Parse(location); perr == nil && u.Path != "" {
				currentPath = u.RequestURI()
			}
			isRedirectHop = true
			continue
		}
		break
	}

	if bestResult == nil {
		return nil, fmt.Errorf("bad_reply")
	}

	if tlsState != nil {
		bestResult.CertCN, bestResult.CertSAN = extractCertInfo(tlsState)
	}

	// ── گام ۴: favicon hash — روی همان اتصال keep-alive و داخل rate limiter ──
	// (در v2 گوریوتن fire-and-forget بود که rate limiter را دور می‌زد)
	if cfg.FaviconHash && !connDirty && bestResult.StatusCode == 200 {
		fetchIt := bucket == nil
		if bucket != nil {
			fetchIt = bucket.Wait(ctx) == nil
		}
		if fetchIt {
			fetchFaviconHash(conn, br, target, scheme, profile, bestResult, cfg)
		}
	}

	bestResult.InternalIPs = dedupeJoin(leakedIPs)
	bestResult.Redirects = strings.Join(allRedirects, " -> ")
	return bestResult, nil
}

// fetchFaviconHash — درخواست /favicon.ico از همان اتصال و محاسبه mmh3
func fetchFaviconHash(conn net.Conn, br *bufio.Reader, target Target, scheme string,
	profile *BrowserProfile, res *ScanResult, cfg *Config) {

	defer func() { _ = recover() }()

	conn.SetDeadline(time.Now().Add(cfg.Timeout))
	reqStr := buildFaviconRequest(target.IP, target.Port, scheme, profile)
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		return
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	io.CopyN(io.Discard, resp.Body, 256<<10)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(raw) == 0 {
		return
	}
	res.FaviconHash = shodanFaviconHash(raw)
	if faviconDB != nil {
		if entry, ok := faviconDB[res.FaviconHash]; ok {
			res.FaviconApp = entry.Name
		}
	}
}

// probeTarget — هر دو scheme را امتحان می‌کند و اولین موفقیت را برمی‌گرداند
func probeTarget(ctx context.Context, target Target, cfg *Config,
	proxyAddr string, bucket *TokenBucket, srcIP net.IP) *ScanResult {

	res := &ScanResult{IP: target.IP, Port: target.Port, Ts: time.Now().Unix()}

	// Rate limiting
	if bucket != nil {
		if err := bucket.Wait(ctx); err != nil {
			res.Error = "rate_limit_cancelled"
			return res
		}
	}

	// Jitter
	if cfg.JitterMs > 0 {
		time.Sleep(time.Duration(rand.Intn(cfg.JitterMs)) * time.Millisecond)
	}

	profile := profileForIP(target.IP, cfg.Browser)

	tryHTTPS := tlsPorts[target.Port]
	schemes := []string{"http"}
	if tryHTTPS {
		schemes = []string{"https", "http"}
	}

	var lastErr error
	for _, scheme := range schemes {
		if ctx.Err() != nil {
			break
		}
		r, err := probeScheme(ctx, target, scheme, cfg, profile, proxyAddr, bucket, srcIP)
		if err != nil {
			lastErr = err
			continue
		}
		return r
	}

	if lastErr != nil {
		res.Error = classifyConnErr(lastErr)
	} else {
		res.Error = "not_http"
	}
	return res
}

// ═══════════════════════════════════════════════════════════════════
// Worker
// ═══════════════════════════════════════════════════════════════════

func worker(id int, ctx context.Context, targets <-chan Target, results chan<- *ScanResult,
	cfg *Config, pr *ProxyRotator, sr *SourceIPRotator, bucket *TokenBucket, wg *sync.WaitGroup) {

	defer wg.Done()
	for target := range targets {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Think time — شبیه‌سازی تأخیر انسانی بین درخواست‌ها
		if cfg.ThinkTimeMs > 0 {
			time.Sleep(time.Duration(rand.Intn(cfg.ThinkTimeMs)) * time.Millisecond)
		}

		proxyAddr := pr.Next()
		srcIP := sr.Next()

		t0 := time.Now()
		result := probeTarget(ctx, target, cfg, proxyAddr, bucket, srcIP)
		result.ElapsedMs = time.Since(t0).Milliseconds()

		if proxyAddr != "" && result.Error != "" {
			pr.ReportFailure(proxyAddr)
		}

		results <- result
	}
}

func spawnWorkers(ctx context.Context, targets <-chan Target, results chan<- *ScanResult,
	cfg *Config, pr *ProxyRotator, sr *SourceIPRotator, bucket *TokenBucket) *sync.WaitGroup {

	var wg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go worker(i, ctx, targets, results, cfg, pr, sr, bucket, &wg)
	}
	return &wg
}

// ═══════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════

func main() {
	cfg := &Config{}
	flag.StringVar(&cfg.InputFile, "i", "-", "Input file (ip:port per line, or - for stdin)")
	flag.StringVar(&cfg.OutputFile, "o", "", "Output file (JSON lines); default=stdout")
	flag.StringVar(&cfg.InputFormat, "format", "plain", "Input format: plain, masscan")
	flag.IntVar(&cfg.Concurrency, "c", 200, "Concurrent workers")
	flag.IntVar(&cfg.RateLimit, "rate", 500, "Max requests/sec (0=unlimited)")
	flag.IntVar(&cfg.Timeout, "timeout", 8000, "Request timeout in milliseconds")
	flag.IntVar(&cfg.JitterMs, "jitter", 20, "Random delay 0-N ms before each request")
	flag.IntVar(&cfg.ThinkTimeMs, "think", 50, "Browser think time 0-N ms between requests")
	flag.StringVar(&cfg.ProxyFile, "proxy", "", "Proxy file (socks5://... or http://... per line)")
	flag.StringVar(&cfg.SourceIPsFile, "source-ips", "", "Source IP file for rotation (one IP per line)")
	flag.StringVar(&cfg.Browser, "browser", "random", "Browser profile: chrome, firefox, edge, random")
	flag.IntVar(&cfg.MaxBody, "max-body", 131072, "Max response body bytes")
	flag.IntVar(&cfg.MaxRedirects, "max-redirects", 3, "Max redirect hops")
	flag.BoolVar(&cfg.FaviconHash, "favicon", true, "Fetch /favicon.ico and compute shodan-style mmh3 hash")
	flag.StringVar(&cfg.FaviconDB, "favicon-db", "", "JSON file: favicon hash -> {name, category}")
	flag.BoolVar(&cfg.Adaptive, "adaptive", true, "Adaptive rate: auto-slow-down on high error rate (WAF throttling)")
	flag.BoolVar(&cfg.Retry, "retry", true, "Second pass over transiently failed targets")
	flag.IntVar(&cfg.Shard, "shard", 1, "Shard index (1-based)")
	flag.IntVar(&cfg.Shards, "shards", 1, "Total number of shards")
	flag.Parse()

	cfg.Timeout = cfg.Timeout * time.Millisecond

	log.Printf("=== Stealth L7 Prober v%s ===", Version)
	log.Printf("Workers: %d | Rate: %d/s | Browser: %s | Timeout: %v | Adaptive: %v | Retry: %v",
		cfg.Concurrency, cfg.RateLimit, cfg.Browser, cfg.Timeout, cfg.Adaptive, cfg.Retry)
	if cfg.Shards > 1 {
		log.Printf("Shard: %d/%d", cfg.Shard, cfg.Shards)
	}

	// پراکسی‌ها
	pr, err := NewProxyRotator(cfg.ProxyFile)
	if err != nil {
		log.Fatalf("[!] proxy load: %v", err)
	}

	// source IP ها
	sr, err := NewSourceIPRotator(cfg.SourceIPsFile)
	if err != nil {
		log.Fatalf("[!] source IP load: %v", err)
	}

	// favicon DB
	loadFaviconDB(cfg.FaviconDB)

	// تارگت‌ها
	targetCh, err := loadTargets(cfg)
	if err != nil {
		log.Fatalf("[!] target load: %v", err)
	}

	// Rate limiter با ramp-up ۱۵ ثانیه‌ای
	var bucket *TokenBucket
	if cfg.RateLimit > 0 {
		rampDur := 15 * time.Second
		bucket = NewTokenBucket(cfg.RateLimit, cfg.RateLimit/2, rampDur)
	}
	gov := &AdaptiveGovernor{enabled: cfg.Adaptive, bucket: bucket}

	// خروجی
	var outW *os.File = os.Stdout
	var err2 error
	if cfg.OutputFile != "" {
		outW, err2 = os.Create(cfg.OutputFile)
		if err2 != nil {
			log.Fatalf("[!] output: %v", err2)
		}
		defer outW.Close()
	}
	bw := bufio.NewWriter(outW)
	defer bw.Flush()
	enc := json.NewEncoder(bw)

	// خاموشی نرم
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[!] Shutting down gracefully...")
		cancel()
	}()

	var total, webCount, errCount int64

	// ── پاس اول ──
	resultCh := make(chan *ScanResult, 10000)
	wg := spawnWorkers(ctx, targetCh, resultCh, cfg, pr, sr, bucket)
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var retryList []Target
	seen := make(map[string]bool)
	t0 := time.Now()

	for result := range resultCh {
		total++
		if result.Scheme != "" {
			atomic.AddInt64(&webCount, 1)
		}
		if result.Error != "" {
			atomic.AddInt64(&errCount, 1)
		}
		gov.Record(result.Error != "")

		key := result.IP + ":" + strconv.Itoa(result.Port)
		if _, dup := seen[key]; !dup {
			seen[key] = true
			if cfg.Retry && isTransientError(result.Error) && len(retryList) < 1000000 {
				retryList = append(retryList, Target{IP: result.IP, Port: result.Port})
			}
		}

		enc.Encode(result)
		if total%1000 == 0 {
			log.Printf("  [progress] %d probed | web: %d | errors: %d | %.0fs",
				total, atomic.LoadInt64(&webCount), atomic.LoadInt64(&errCount), time.Since(t0).Seconds())
		}
	}
	log.Printf("[pass 1] %d probed in %s | web: %d | errors: %d",
		total, fmtDur(time.Since(t0)), atomic.LoadInt64(&webCount), atomic.LoadInt64(&errCount))

	// ── پاس دوم (retry خطاهای گذرا) ──
	if cfg.Retry && len(retryList) > 0 && ctx.Err() == nil {
		log.Printf("[pass 2] retrying %d transiently failed targets...", len(retryList))
		retryCh := make(chan Target, 1024)
		go func() {
			defer close(retryCh)
			for _, t := range retryList {
				select {
				case retryCh <- t:
				case <-ctx.Done():
					return
				}
			}
		}()

		resultCh2 := make(chan *ScanResult, 10000)
		wg2 := spawnWorkers(ctx, retryCh, resultCh2, cfg, pr, sr, bucket)
		go func() {
			wg2.Wait()
			close(resultCh2)
		}()

		var rTotal, rWeb int64
		for result := range resultCh2 {
			rTotal++
			if result.Scheme != "" {
				rWeb++
				atomic.AddInt64(&webCount, 1)
			}
			enc.Encode(result)
			if rTotal%1000 == 0 {
				log.Printf("  [retry progress] %d probed | recovered: %d", rTotal, rWeb)
			}
		}
		log.Printf("[pass 2] %d retried | %d recovered", rTotal, rWeb)
	}

	log.Printf("=== Done: %d total | %d web | %d errors ===", total, webCount, errCount)
}

func fmtDur(d time.Duration) string {
	sec := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d:%02d", sec/3600, (sec%3600)/60, sec%60)
}
