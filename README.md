# cdn-poison


A Python tool that passively detects web cache deception vulnerabilities through HTTP header analysis. No exploitation — detection only.

Built as a hands-on exploration of [PortSwigger's web cache deception research](https://portswigger.net/web-security/web-cache-deception) and the [Cloudflare CDN deanonymization writeup] that went viral in 2024.

---

## What is Web Cache Deception?

A CDN like Cloudflare sits between users and origin servers, caching static files (`.css`, `.js`, `.png`) to serve them faster. The attack exploits a mismatch between what the **origin server** thinks it's serving and what the **CDN thinks it should cache**.

```
Normal request:
  victim  →  GET /account          →  server returns account page (private)
                                       CDN: "dynamic page, don't cache"  ✓

Cache deception attack:
  attacker tricks victim to load:
  victim  →  GET /account/x.css    →  server still returns account page
                                       CDN: "oh, .css file — I'll cache that"  ✗
  attacker →  GET /account/x.css   →  gets victim's cached private data
```

The attacker just needs to send the victim a link. Once clicked, the victim's private data is publicly cached on the CDN edge server.

---

## What this tool checks

| Check | What it detects | Severity |
|---|---|---|
| **Path Confusion** | Does appending `.css` to a path get cached by the CDN as a public asset? | HIGH |
| **Cache-Control Headers** | Do sensitive paths (`/account`, `/profile`, `/dashboard`) send `no-store`? | HIGH |
| **CF Caches Dynamic Paths** | Does Cloudflare cache `/account/x.css` after one request (MISS → HIT)? | HIGH |
| **Vary: Cookie Header** | Do cacheable responses include `Vary: Cookie` to prevent cross-user cache sharing? | MEDIUM |
| **Cookie + Cache Conflict** | Does a `Set-Cookie` response also allow caching? | MEDIUM |

### What a vulnerable response looks like

```http
CF-Cache-Status: HIT
Cache-Control: public, max-age=31536000
```

### What a secure response looks like

```http
CF-Cache-Status: DYNAMIC
Cache-Control: private, no-store
```

---

## Installation

```bash
git clone https://github.com/yourusername/cache-deception-detector
cd cache-deception-detector
pip install requests rich
```

No other dependencies. Python 3.8+.

---

## Usage

**Scan a single site:**
```bash
python cli.py discord.com
```

**Scan multiple sites at once:**
```bash
python cli.py discord.com signal.org namecheap.com
```

**Plain output (no rich formatting):**
```bash
python scanner.py discord.com
```

**Import as a module in your own script:**
```python
from scanner import scan

result = scan("https://discord.com")

print(result.risk_score)   # 0–100
print(result.risk_level)   # SAFE / LOW / MEDIUM / HIGH

for check in result.checks:
    print(check.name)      # "Path Confusion" etc.
    print(check.passed)    # True = safe, False = flagged
    print(check.severity)  # LOW / MEDIUM / HIGH
    print(check.detail)    # full human-readable explanation
    print(check.evidence)  # raw header values dict
```

---

## Sample output

```
╭─────────────────────────────────────────────────────────────╮
│  Web Cache Deception Detector                               │
│  Educational tool — passive header analysis only.           │
╰─────────────────────────────────────────────────────────────╯

────────────────────── discord.com ───────────────────────────
  Cloudflare ✓  Server: cloudflare  Scan time: 8.93s

 Check                    Result      Severity   Detail
 ──────────────────────────────────────────────────────────────────────────────
 Path Confusion           ✓ SAFE      —          CDN returned DYNAMIC. Edge proxy
                                                 obeying origin Cache-Control.
 Cache-Control Headers    ✓ SAFE      —          All 6 sensitive paths send proper
                                                 Cache-Control headers.
 CF Caches Dynamic Paths  ⚠ FLAGGED   🔴 HIGH    Cloudflare cached /account/auied
                                                 uxn.css (MISS→HIT). A path rese-
                                                 mbling a user account endpoint
                                                 was cached after one request.
 Vary: Cookie Header      ⚠ FLAGGED   🟠 MEDIUM  Cacheable paths ['/'] missing
                                                 Vary: Cookie — responses could be
                                                 shared across users.
 Cookie + Cache Conflict  ⚠ FLAGGED   🟠 MEDIUM  Homepage sets cookies AND is
                                                 cacheable.

  Risk Score  ████████░░░░░░░░░░░░  45/100 — MEDIUM

╭─── Recommendations ─────────────────────────────────────────╮
│ • Add Cloudflare Cache Rule: bypass cache for URI paths     │
│   containing /account, /profile, /user, /dashboard         │
│ • Add Vary: Cookie to cacheable responses that depend on    │
│   session state                                             │
│ • Never cache responses that include Set-Cookie headers     │
╰─────────────────────────────────────────────────────────────╯
```

---

## How it works

All checks are **passive** — the tool only sends GET requests and reads response headers. It never modifies state, sends POST requests, or accesses any private data.

```
Step 1  GET /randomslug.css          →  cf-cache-status: MISS  (expected)
        wait 1.2s
Step 2  GET /randomslug.css          →  cf-cache-status: HIT?  (vulnerable)
                                        cf-cache-status: DYNAMIC? (safe)

Step 3  GET /account                 →  Cache-Control: no-store? (safe)
        GET /profile                     Cache-Control: public?   (flagged)
        GET /dashboard ...

Step 4  GET /account/randomslug.css  →  MISS → HIT = vulnerable
        wait 1.2s
        GET /account/randomslug.css

Step 5  GET /                        →  Vary: Cookie present?
                                        Set-Cookie + cacheable = conflict?
```

---

#Project Structure 
(This currently is dynamic, will change accordingly)

## Ethical use

Only scan domains you own or have explicit written permission to test.

This tool sends only GET requests to publicly accessible endpoints and reads only HTTP response headers. It cannot access private user data, authenticate as any user, or modify server state in any way.

---

## References

- [Web Cache Deception Attack — PortSwigger Research](https://portswigger.net/research/web-cache-deception)  
- [OWASP: Web Cache Deception](https://owasp.org/www-community/attacks/Cache_Poisoning)
- [Cloudflare Cache Deception Armor](https://developers.cloudflare.com/cache/cache-security/cache-deception-armor/)

---
