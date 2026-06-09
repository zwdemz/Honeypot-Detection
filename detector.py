"""
Honeypot Detection Tool v2.0

Features:
  - URL deduplication & multi-threaded scanning
  - Token bucket rate limiting
  - Cloud vendor honeypot signatures (Alibaba, Tencent, Huawei, AWS, Azure, GCP)
  - Open-source honeypot fingerprinting (HFish, T-Pot, Cowrie, etc.)
  - Auto retry with exponential backoff
  - Proxy support
  - JSON / text output
"""

import re
import time
import json
import argparse
import logging
import threading
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("honeypot")


class TokenBucket:
    """Token bucket rate limiter (thread-safe)."""

    def __init__(self, rate: float):
        self._rate = rate
        self._tokens = 0.0
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def consume(self):
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self._tokens + elapsed * self._rate, self._rate)
            if self._tokens < 1.0:
                sleep = (1.0 - self._tokens) / self._rate
                time.sleep(sleep)
                self._tokens = 0.0
                self._last = now + sleep
            else:
                self._tokens -= 1.0
                self._last = now


def load_urls(path: str) -> list[str]:
    """Load and deduplicate URLs from file."""
    try:
        with open(path) as f:
            return list(dict.fromkeys(line.strip() for line in f if line.strip()))
    except Exception as e:
        log.error("Failed to read %s: %s", path, e)
        raise SystemExit(1)


def make_session(proxy: Optional[str] = None) -> requests.Session:
    """Create a reusable session with retry logic."""
    retries = Retry(total=2, backoff_factor=0.5, allowed_methods={"GET"})
    adapter = HTTPAdapter(max_retries=retries, pool_maxsize=50)
    s = requests.Session()
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


# ============================================================
# Honeypot Signature Database
# ============================================================

# --- Content-based signatures ---
CONTENT_SIGNATURES: list[tuple[str, re.Pattern]] = [
    # Alibaba Cloud Honeypot
    ("aliyun_honeypot", re.compile(
        r"(?:阿里云|Aliyun)\s*(?:蜜罐|安全|威胁|诱捕|honeypot)", re.I
    )),
    ("aliyun_cloudshield", re.compile(
        r"cloudshield|aliyunddos|waf\.aliyuncs\.com", re.I
    )),
    # Tencent Cloud Honeypot
    ("tencent_honeypot", re.compile(
        r"(?:腾讯云|Tencent)\s*(?:蜜罐|安全|主机安全|威胁|honeypot)", re.I
    )),
    ("tencent_waf", re.compile(
        r"waf\.tencentcloud\.com|t-sec|tencent\s*cloud\s*waf", re.I
    )),
    # Huawei Cloud Honeypot
    ("huawei_honeypot", re.compile(
        r"(?:华为云|Huawei)\s*(?:蜜罐|安全|威胁|honeypot)", re.I
    )),
    ("huawei_waf", re.compile(
        r"hwclouds\.com.*waf|hws.*waf|huawei.*cloud.*waf", re.I
    )),
    # AWS Honeypot / Trap
    ("aws_honeypot", re.compile(
        r"(?:aws|amazon)\s*(?:honeypot|honeytoken|canary|trap|decoy)", re.I
    )),
    ("aws_guardduty", re.compile(
        r"guardduty|amazon\s*guardduty", re.I
    )),
    # Azure Honeypot
    ("azure_honeypot", re.compile(
        r"(?:azure|microsoft)\s*(?:honeypot|deception|canary|decoy|sentinel)", re.I
    )),
    ("azure_defender", re.compile(
        r"defender\s*for\s*cloud|microsoft\s*defender\s*for\s*cloud", re.I
    )),
    # GCP Honeypot
    ("gcp_honeypot", re.compile(
        r"(?:gcp|google\s*cloud)\s*(?:honeypot|deception|canary|decoy)", re.I
    )),
    ("gcp_chronical", re.compile(
        r"chronicle|google\s*cloud\s*security\s*command\s*center", re.I
    )),
    # HFish
    ("hfish", re.compile(
        r"hfish|(?:HFish|Hfish)\s*(?:蜜罐|honeypot|平台)|lang=\"cn\"[^>]*HFish", re.I
    )),
    # T-Pot
    ("tpot", re.compile(
        r"t-pot|tpot|telekom\s*honeypot|dtag\s*honeypot", re.I
    )),
    # Cowrie / Kippo SSH honeypot
    ("cowrie", re.compile(
        r"cowrie|cowrie\s*ssh|kippo\s*honeypot", re.I
    )),
    ("kippo", re.compile(
        r"kippo|kippo\s*honeypot", re.I
    )),
    # Conpot (ICS honeypot)
    ("conpot", re.compile(
        r"conpot|conpot\s*ics|industrial\s*control\s*honeypot", re.I
    )),
    # Dionaea
    ("dionaea", re.compile(
        r"dionaea|dionaea\s*honeypot", re.I
    )),
    # Glastopf / Snake (web honeypot)
    ("glastopf", re.compile(
        r"glastopf|snake\s*honeypot", re.I
    )),
    # Honeyd
    ("honeyd", re.compile(
        r"honeyd|honeyd\s*daemon|niels\s*provos", re.I
    )),
    # Honeytrap
    ("honeytrap", re.compile(
        r"honeytrap|honeytrap\s*daemon", re.I
    )),
    # OpenCanary
    ("opencanary", re.compile(
        r"opencanary|open\s*canary", re.I
    )),
    # Modern Honey Network
    ("mhn", re.compile(
        r"mhn|modern\s*honey\s*network|honeymap", re.I
    )),
    # Common default honeypot HTML artifacts
    ("default_page", re.compile(
        r"(?:Apache2?|Nginx|IIS|Tomcat)\s+(?:Default\s+)?(?:Page|Test|Welcome)", re.I
    )),
    ("fake_form", re.compile(
        r'<input[^>]*?(?:type=["\']?(?:hidden|text)["\']?[^>]*?\s+){5,}', re.I
    )),
    ("empty_links", re.compile(
        r'<a\s+href=["\']#["\']\s*>', re.I
    )),
    ("honeypot_token", re.compile(
        r"honeypot|honeyport|honey_token|honey_net|honey_pot", re.I
    )),
    ("admin_login", re.compile(
        r'<input[^>]*name=["\']?(?:user|pass|login|pwd|password)["\']?', re.I
    )),
]

# --- Header-based signatures ---
HEADER_SIGNATURES: list[tuple[str, str]] = [
    ("aliyun_waf", "aliyun"),
    ("tencent_waf", "tencent"),
    ("huawei_waf", "huawei"),
    ("cloudflare", "cloudflare"),
    ("akamai", "akamai"),
]

# --- Response time anomaly threshold ---
RESP_TIME_THRESHOLD = 10.0  # seconds


def check_headers(resp: requests.Response) -> list[str]:
    """Check response headers for WAF / proxy fingerprints."""
    triggers = []
    server = resp.headers.get("Server", "")
    powered = resp.headers.get("X-Powered-By", "")
    frame = resp.headers.get("X-Frame-Options", "")
    csp = resp.headers.get("Content-Security-Policy", "")

    for name, keyword in HEADER_SIGNATURES:
        if keyword.lower() in server.lower() or keyword.lower() in powered.lower():
            triggers.append(name)

    # Honeypot / deception specific headers
    if "X-Honeypot" in resp.headers:
        triggers.append("X-Honeypot-Header")
    if "X-Canary" in resp.headers:
        triggers.append("X-Canary-Header")
    if "X-Decoy" in resp.headers:
        triggers.append("X-Decoy-Header")

    # Too restrictive CSP (often in deception platforms)
    if "sandbox" in csp and "self" not in csp:
        triggers.append("RestrictiveCSP")

    # Unusual frame options
    if frame and frame.lower() not in ("deny", "sameorigin"):
        triggers.append(f"UnusualXFrame({frame})")

    return triggers


def detect_honeypot(
    url: str,
    bucket: Optional[TokenBucket] = None,
    proxy: Optional[str] = None,
) -> dict:
    """Scan a single URL for honeypot indicators."""
    if bucket:
        bucket.consume()

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    session = make_session(proxy)
    try:
        resp = session.get(url, headers=headers, timeout=15, verify=False, stream=True)
        resp.raise_for_status()
        final_url = resp.url
        text = resp.text
    except Exception as e:
        session.close()
        return {"url": url, "status": "error", "reason": str(e)[:120]}
    session.close()

    triggers = []

    # --- 1. Set-Cookie count ---
    try:
        cookies = resp.raw.headers.getlist("Set-Cookie")
    except Exception:
        cookies = []
    if not cookies:
        cookie_header = resp.headers.get("Set-Cookie", "")
        if cookie_header:
            cookies = [c.strip() for c in cookie_header.split(",") if c.strip()]
    if len(cookies) > 5:
        triggers.append(f"Set-Cookie({len(cookies)})")

    # --- 2. HTML comment density ---
    comments = re.findall(r"<!--(.*?)-->", text, re.DOTALL)
    comment_lines = sum(c.count("\n") + 1 for c in comments)
    if comment_lines > 500:
        triggers.append(f"Comments({comment_lines} lines)")

    # --- 3. Content-based signatures ---
    for name, pattern in CONTENT_SIGNATURES:
        if pattern.search(text):
            triggers.append(name)

    # --- 4. Header-based signatures ---
    triggers.extend(check_headers(resp))

    # --- 5. Low entropy / high repetition ---
    words = re.findall(r"\w+", text)
    if words:
        unique_ratio = len(set(words)) / len(words)
        if unique_ratio < 0.15:
            triggers.append(f"LowEntropy({unique_ratio:.2f})")

    # --- 6. Content-Length mismatch ---
    declared = resp.headers.get("Content-Length")
    if declared and text:
        diff = abs(int(declared) - len(text.encode()))
        if diff > 1024:
            triggers.append(f"SizeMismatch({diff} bytes)")

    # --- 7. Missing security headers (common on real apps, absent on many honeypots) ---
    security_headers = ["X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security"]
    missing = [h for h in security_headers if h not in resp.headers]
    if len(missing) == len(security_headers):
        triggers.append("NoSecHeaders")

    return {
        "url": final_url,
        "status": "honeypot" if triggers else "normal",
        "triggers": triggers,
        "elapsed": round(resp.elapsed.total_seconds(), 3),
        "code": resp.status_code,
    }


def save_results(results: list[dict], path: str):
    """Deduplicate and save results."""
    seen: set[str] = set()
    with open(path, "w") as f:
        for r in results:
            if r["url"] in seen:
                continue
            seen.add(r["url"])
            f.write(f"{r['url']}\n")
            if r.get("triggers"):
                f.write(f"  triggers: {', '.join(r['triggers'])}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Honeypot Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-i", "--input", required=True, help="URL list file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="thread count (default: 10)")
    parser.add_argument("-r", "--rate", type=float, help="rate limit (requests/sec)")
    parser.add_argument("-o", "--output", default=".", help="output directory (default: current)")
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--json", action="store_true", help="JSON output instead of files")
    args = parser.parse_args()

    bucket = TokenBucket(args.rate) if args.rate else None
    urls = load_urls(args.input)
    log.info("Loaded %d unique URLs", len(urls))

    honeypots: list[dict] = []
    normals: list[dict] = []
    errors: list[dict] = []

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        fut_map = {
            pool.submit(detect_honeypot, u, bucket, args.proxy): u for u in urls
        }
        for i, fut in enumerate(as_completed(fut_map), 1):
            try:
                r = fut.result()
                if r["status"] == "honeypot":
                    honeypots.append(r)
                elif r["status"] == "normal":
                    normals.append(r)
                else:
                    errors.append(r)
            except Exception as e:
                errors.append({"url": fut_map[fut], "status": "error", "reason": str(e)[:120]})

            log.info(
                "Progress [%d/%d] honeypot=%d normal=%d error=%d",
                i, len(urls), len(honeypots), len(normals), len(errors),
            )

    # output
    if args.json:
        report = {
            "summary": {
                "total": len(urls),
                "honeypot": len(honeypots),
                "normal": len(normals),
                "error": len(errors),
            },
            "honeypots": honeypots,
            "normals": [{"url": r["url"]} for r in normals],
            "errors": errors,
        }
        json.dump(report, open(Path(args.output) / "report.json", "w"), indent=2, ensure_ascii=False)
    else:
        out_dir = Path(args.output)
        save_results(honeypots, str(out_dir / "honeypot.txt"))
        save_results(normals, str(out_dir / "normal.txt"))

    print()
    print("=" * 50)
    print("  Scan Complete")
    print("=" * 50)
    print(f"  Total      : {len(urls)}")
    print(f"  Honeypot   : {len(honeypots)}")
    print(f"  Normal     : {len(normals)}")
    print(f"  Error      : {len(errors)}")
    print("=" * 50)


if __name__ == "__main__":
    main()
