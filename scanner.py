"""
Web Cache Deception Detector
Educational tool — detects potential cache deception vulnerabilities
via passive header analysis. Does NOT exploit anything.
"""

import requests
import time
import random
import string
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

SENSITIVE_PATHS = [
    "/account", "/profile", "/dashboard", "/settings",
    "/user", "/admin", "/login", "/api/user", "/me",
    "/orders", "/billing", "/private",
]

STATIC_EXTENSIONS = [".css", ".js", ".png", ".jpg", ".svg", ".ico", ".woff"]

RISK_WEIGHTS = {
    "path_confusion":        30,
    "missing_cache_control": 25,
    "cf_caches_dynamic":     25,
    "no_vary_header":        10,
    "cacheable_cookies":     10,
}


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str
    severity: str  # LOW / MEDIUM / HIGH
    evidence: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    domain: str
    checks: list = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "UNKNOWN"
    is_cloudflare: bool = False
    server: str = ""
    scan_time: float = 0.0
    error: Optional[str] = None


def get(url: str, timeout: int = 8) -> Optional[requests.Response]:
    try:
        return requests.get(url, headers=HEADERS, timeout=timeout,
                            allow_redirects=True, stream=False)
    except requests.exceptions.RequestException:
        return None


def rand_path(ext: str = "") -> str:
    slug = ''.join(random.choices(string.ascii_lowercase, k=8))
    return f"/{slug}{ext}"


def is_cloudflare(resp: requests.Response) -> bool:
    h = {k.lower() for k in resp.headers}
    return "cf-ray" in h or "cf-cache-status" in h


def get_cache_status(resp: requests.Response) -> str:
    return (
        resp.headers.get("cf-cache-status")
        or resp.headers.get("x-cache")
        or resp.headers.get("x-cache-status")
        or "UNKNOWN"
    ).upper()


def check_path_confusion(base_url: str) -> CheckResult:
    """
    Appends a static extension to a random path, requests it twice,
    and checks whether the CDN cached it as a public static asset.
    This is the core web cache deception signal.
    """
    slug = rand_path()
    ext = random.choice(STATIC_EXTENSIONS)
    path_with_ext = base_url + slug + ext

    # First request — should be MISS
    r1 = get(path_with_ext)
    time.sleep(1.2)
    # Second request — did CDN cache it?
    r2 = get(path_with_ext)

    if not r1 or not r2:
        return CheckResult(
            name="Path Confusion",
            passed=True,
            detail="Could not reach server to probe.",
            severity="LOW",
        )

    s1 = get_cache_status(r1)
    s2 = get_cache_status(r2)
    cc = r2.headers.get("cache-control", "").lower()

    cdn_cached   = s2 == "HIT"
    cdn_safe     = s2 in ("DYNAMIC", "BYPASS", "MISS")
    public_cc    = "public" in cc
    private_cc   = "private" in cc or "no-store" in cc

    if cdn_cached and public_cc:
        vulnerable = True
        severity = "HIGH"
        detail = (
            f"CDN cached {slug}{ext} as a public asset "
            f"(cf-cache-status: HIT, Cache-Control: {cc or '?'}). "
            "An attacker can distribute this URL — when an authenticated victim loads it, "
            "their account data is stored on the edge server for anyone to retrieve."
        )
    elif cdn_safe or private_cc:
        vulnerable = False
        severity = "LOW"
        detail = (
            f"CDN correctly marked response as {s2} "
            f"(Cache-Control: {cc or '?'}). "
            "Edge proxy is obeying origin Cache-Control or has Cache Deception Armor enabled."
        )
    elif cdn_cached and not public_cc:
        vulnerable = True
        severity = "MEDIUM"
        detail = (
            f"CDN cached {slug}{ext} (HIT) but Cache-Control is ambiguous "
            f"({cc or 'missing'}). "
            "May be exploitable depending on what content the path returns when authenticated."
        )
    else:
        vulnerable = False
        severity = "LOW"
        detail = (
            f"cf-cache-status: {s1} → {s2}. "
            "No caching of extension-appended path detected."
        )

    return CheckResult(
        name="Path Confusion",
        passed=not vulnerable,
        severity=severity,
        detail=detail,
        evidence={
            "path_tested": slug + ext,
            "first_cf_cache_status": s1,
            "second_cf_cache_status": s2,
            "cache_control": cc or "missing",
            "content_type": r2.headers.get("content-type", "unknown"),
            "http_status": r2.status_code,
        }
    )


def check_cache_control(base_url: str) -> CheckResult:
    """
    Do sensitive-looking paths send proper Cache-Control: no-store/private headers?
    Missing protection on /account, /profile etc. is a risk signal.
    """
    bad_paths = []
    checked = []

    for path in SENSITIVE_PATHS[:6]:
        r = get(base_url + path)
        if not r:
            continue
        if r.status_code not in (200, 401, 403):
            continue

        cc = r.headers.get("cache-control", "").lower()
        pragma = r.headers.get("pragma", "").lower()
        has_protection = (
            "no-store" in cc or "private" in cc or "no-cache" in cc
            or "no-cache" in pragma
        )
        checked.append(path)
        if not has_protection:
            bad_paths.append({
                "path": path,
                "status": r.status_code,
                "cache-control": r.headers.get("cache-control", "missing"),
            })
        time.sleep(0.2)

    if not checked:
        return CheckResult(
            name="Cache-Control Headers",
            passed=True,
            detail="No sensitive paths responded — could not evaluate.",
            severity="LOW",
        )

    vulnerable = len(bad_paths) > 0
    return CheckResult(
        name="Cache-Control Headers",
        passed=not vulnerable,
        severity="HIGH" if len(bad_paths) >= 2 else "MEDIUM" if vulnerable else "LOW",
        detail=(
            f"{len(bad_paths)}/{len(checked)} sensitive paths lack "
            f"Cache-Control: no-store/private. "
            f"Paths: {', '.join(p['path'] for p in bad_paths)}"
            if vulnerable else
            f"All {len(checked)} tested sensitive paths send proper Cache-Control headers."
        ),
        evidence={"unprotected_paths": bad_paths, "checked_paths": checked}
    )


def check_cf_caches_dynamic(base_url: str) -> CheckResult:
    """
    Does Cloudflare cache a path that looks like /account/something.css?
    First request = MISS (expected). Second request = HIT on a user-path = bad.
    """
    slug = ''.join(random.choices(string.ascii_lowercase, k=6))
    path = f"/account/{slug}.css"
    full = base_url + path

    r1 = get(full)
    time.sleep(1.2)
    r2 = get(full)

    if not r1 or not r2:
        return CheckResult(
            name="CF Caches Dynamic Paths",
            passed=True,
            detail="Could not reach URL to test.",
            severity="LOW",
        )

    s1 = get_cache_status(r1)
    s2 = get_cache_status(r2)
    cc = r2.headers.get("cache-control", "").lower()
    cf_hit_on_dynamic = s2 == "HIT" and r2.status_code == 200

    return CheckResult(
        name="CF Caches Dynamic Paths",
        passed=not cf_hit_on_dynamic,
        severity="HIGH" if cf_hit_on_dynamic else "LOW",
        detail=(
            f"Cloudflare cached {path} (MISS → HIT, Cache-Control: {cc or '?'}). "
            "A path resembling a user account endpoint was cached after one request — "
            "core web cache deception condition confirmed."
            if cf_hit_on_dynamic else
            f"cf-cache-status: {s1} → {s2}. "
            "Cloudflare did not cache this dynamic-looking account path."
        ),
        evidence={
            "url_tested": full,
            "first_request_cache_status": s1,
            "second_request_cache_status": s2,
            "cache_control": cc or "missing",
            "http_status": r2.status_code,
        }
    )


def check_vary_header(base_url: str) -> CheckResult:
    """
    Does the server use Vary: Cookie on cacheable responses?
    Missing Vary: Cookie means cached responses may be shared across users.
    """
    bad = []
    for path in ["/", "/account", "/profile"]:
        r = get(base_url + path)
        if not r or r.status_code not in (200, 401, 403):
            continue
        vary = r.headers.get("vary", "").lower()
        cc = r.headers.get("cache-control", "").lower()
        is_cacheable = "no-store" not in cc and "private" not in cc
        has_cookie_vary = "cookie" in vary or "authorization" in vary
        if is_cacheable and not has_cookie_vary:
            bad.append(path)
        time.sleep(0.2)

    vulnerable = len(bad) > 0
    return CheckResult(
        name="Vary: Cookie Header",
        passed=not vulnerable,
        severity="MEDIUM" if vulnerable else "LOW",
        detail=(
            f"Cacheable paths {bad} missing Vary: Cookie — "
            "responses could be shared across different users by the cache layer."
            if vulnerable else
            "Vary headers look correct on all tested paths."
        ),
        evidence={"paths_missing_vary": bad}
    )


def check_cookie_caching(base_url: str) -> CheckResult:
    """
    Does a Set-Cookie response also allow caching?
    Caching a response that sets cookies is dangerous.
    """
    r = get(base_url + "/")
    if not r:
        return CheckResult(
            name="Cookie + Cache Conflict",
            passed=True,
            detail="Could not reach homepage.",
            severity="LOW",
        )

    sets_cookie = "set-cookie" in {k.lower() for k in r.headers}
    cc = r.headers.get("cache-control", "").lower()
    is_cacheable = "no-store" not in cc and "private" not in cc
    vulnerable = sets_cookie and is_cacheable

    return CheckResult(
        name="Cookie + Cache Conflict",
        passed=not vulnerable,
        severity="MEDIUM" if vulnerable else "LOW",
        detail=(
            "Homepage sets cookies AND is cacheable — "
            "a cached response with Set-Cookie could set attacker-controlled cookies on victims."
            if vulnerable else
            "No conflict between Set-Cookie and caching headers detected."
        ),
        evidence={
            "sets_cookie": sets_cookie,
            "cache_control": r.headers.get("cache-control", "missing"),
        }
    )


def calculate_risk(checks: list) -> tuple:
    weight_map = {
        "Path Confusion":           RISK_WEIGHTS["path_confusion"],
        "Cache-Control Headers":    RISK_WEIGHTS["missing_cache_control"],
        "CF Caches Dynamic Paths":  RISK_WEIGHTS["cf_caches_dynamic"],
        "Vary: Cookie Header":      RISK_WEIGHTS["no_vary_header"],
        "Cookie + Cache Conflict":  RISK_WEIGHTS["cacheable_cookies"],
    }
    score = sum(weight_map.get(c.name, 10) for c in checks if not c.passed)

    if score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "SAFE"

    return score, level


def scan(url: str, progress_cb=None) -> ScanResult:
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)

    domain = parsed.netloc or url
    base = f"{parsed.scheme}://{parsed.netloc}"
    result = ScanResult(domain=domain)
    t0 = time.time()

    def log(msg):
        if progress_cb:
            progress_cb(msg)

    log("Connecting to server...")
    r = get(base)
    if not r:
        result.error = "Could not connect to server."
        return result

    result.is_cloudflare = is_cloudflare(r)
    result.server = r.headers.get("server", r.headers.get("Server", "unknown"))

    log("Check 1/5: Path confusion + CDN caching test...")
    result.checks.append(check_path_confusion(base))

    log("Check 2/5: Cache-Control on sensitive paths...")
    result.checks.append(check_cache_control(base))

    log("Check 3/5: Cloudflare dynamic path caching...")
    result.checks.append(check_cf_caches_dynamic(base))

    log("Check 4/5: Vary header analysis...")
    result.checks.append(check_vary_header(base))

    log("Check 5/5: Cookie + cache conflict...")
    result.checks.append(check_cookie_caching(base))

    result.risk_score, result.risk_level = calculate_risk(result.checks)
    result.scan_time = round(time.time() - t0, 2)
    return result


# ── direct usage ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys, json

    url = sys.argv[1] if len(sys.argv) > 1 else "https://discord.com"
    print(f"\nScanning: {url}\n")

    result = scan(url, progress_cb=lambda m: print(f"  {m}"))

    print(f"\n{'='*60}")
    print(f"Domain      : {result.domain}")
    print(f"Cloudflare  : {result.is_cloudflare}")
    print(f"Server      : {result.server}")
    print(f"Risk        : {result.risk_score}/100 — {result.risk_level}")
    print(f"Scan time   : {result.scan_time}s")
    print(f"{'='*60}")

    for c in result.checks:
        status = "SAFE   " if c.passed else f"FLAGGED [{c.severity}]"
        print(f"\n  [{status}] {c.name}")
        print(f"  Detail  : {c.detail}")
        if c.evidence:
            print(f"  Evidence: {json.dumps(c.evidence, indent=4)}")

    print()