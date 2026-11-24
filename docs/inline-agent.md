# Click-time gate: testing a link before the user reaches it

> **Beta (`0.1.0b1`), not production-validated.** The gate's decision logic is unit-tested, but the
> enforcement integrations below have not been run end-to-end against live systems. Pilot in a lab.

The post-delivery scanner catches phishing after mail lands. The **gate** moves the check to the
moment of the click: the user's navigation is held, luretrace's verdict is consulted, and the
click is allowed, blocked, or sent to isolation — before any credential is typed. It also passes
phishing-simulation clicks straight through, so training exercises are never blocked.

The gate is **enforcement-agnostic**. One decision service (`webapp/gate.py`) answers a single
question — allow / block / isolate / scan — and any enforcement point calls it.

```
click → [enforcement point] → POST /check {url} → decision → allow | block | isolate
```

## Three hard truths it is built around

1. **Latency.** A full detonation is 5–30s; nobody waits. The gate never detonates in the hot
   path. It answers from a **verdict cache** that the delivery-time pre-scan fills, so the common
   case (a campaign's shared URL, already scanned for an earlier recipient) is an instant hit.
2. **Unknown ≠ safe.** A link with no verdict yet **fails safe to isolation**, not open. Policy
   can change this (`LURETRACE_UNKNOWN_ACTION`), but the default protects.
3. **Evasion still exists.** A kit that cloaks on IP/geo can show the pre-scanner a clean page.
   Isolation is the answer that doesn't trust the verdict: render the page in a remote browser and
   disable input on detected login forms. Blocking relies on the verdict; isolation does not.

## The decision

| Situation | Default action | Policy env |
| --- | --- | --- |
| Phishing-simulation click | **allow** (and log) | `LURETRACE_SIM_ACTION` |
| Allowlisted domain | allow | `LURETRACE_ALLOWLIST` |
| Not an http(s) link (`javascript:`, `data:`, `file:`) | **block** | — |
| Cached verdict: clean, younger than `LURETRACE_CLEAN_MAX_AGE_H` (24 h) | allow | `LURETRACE_CLEAN_MAX_AGE_H` |
| Cached verdict: clean but older (links are armed after delivery) | as "no verdict yet" | `LURETRACE_CLEAN_MAX_AGE_H` |
| Cached verdict: internal (not detonated) | allow | — |
| Cached verdict: suspicious | **isolate** | `LURETRACE_SUSPICIOUS_ACTION` |
| Cached verdict: malicious | **block** | — |
| No verdict yet | **isolate** | `LURETRACE_UNKNOWN_ACTION` |

Verdicts are looked up by exact URL, then by the URL without its `#fragment` (kits personalise
the fragment per recipient). The cache reads only new scan reports on each refresh, and a refresh
forced by an unknown link is rate-limited, so a flood of unknown links cannot stall the gate.

Simulation recognition (`src/luretrace/simcheck.py`) passes a click through when the landing URL
is on your sim vendor's domains, or when the mail came from a simulation domain **and your mail
system authenticated it** (DMARC pass, or an aligned DKIM pass, in `Authentication-Results`).
A simulation header (`X-PhishTest` and the like) or a `From:` domain on its own is never enough:
both are trivially forged, and a passthrough an attacker can claim is a bypass. That is the
same reasoning behind Microsoft's Advanced Delivery list, which wants the sending domain *and* IP.
If a vendor cannot send authenticated mail, `LURETRACE_SIM_TRUST_UNAUTHENTICATED=1` restores the
weaker behaviour; do that knowingly.

`GET /healthz` returns only `{"ok": true}`. It never echoes the policy, because the allowlist and
simulation domains are exactly where an attacker would host a lure.

## Run it

```bash
pip install -e ".[web]"
export LURETRACE_SCANS=./scans
export LURETRACE_ISOLATION_URL=https://rbi.yourco.com/open   # optional: your RBI entry point
uvicorn webapp.gate:gate_app --port 8090
```

- `POST /check {"url": "...", "headers": {...}}` → `{"action": "...", "reason": "...", ...}`
- `GET /go?u=<url-encoded link>` → 302 to the link (allow), the block page, or a redirect into
  your RBI (isolate). This is the endpoint a link-rewrite service points at.

## Wiring it to each environment

Keep the gate on an internal address, reachable by the enforcement point only.

### 1. Netskope inline + RBI (recommended for your stack)
Netskope is already in the click path. Two ways to use the gate:
- **Verdict feed (simplest):** the pre-scan pushes malicious domains to a Netskope custom URL
  category (the existing IOC export), and a Real-Time Protection policy **blocks** that category
  and **isolates** an "unverified/newly-seen" category. The gate's cache is the source of truth
  for what lands in each category.
- **Decision call (tightest):** where your deployment supports calling an external service on a
  request, call `POST /check` and map `block`→block, `isolate`→Netskope RBI, `allow`→allow.
  Netskope's own Remote Browser Isolation is the isolation target; set `LURETRACE_ISOLATION_URL`
  or route the category to RBI in policy.

### 2. Link-rewrite / redirect service
Rewrite links in inbound mail to `https://gate.yourco.com/go?u=<original>` (the way Safe Links and
Mimecast rewrite). On click, `/go` consults the verdict and redirects, blocks, or isolates. Note
this overlaps with Safe Links/Mimecast rewriting — run it as the second opinion, not a replacement,
and mind double-rewrapping.

### 3. Managed browser extension
An extension intercepts navigation (`webNavigation.onBeforeNavigate`), calls `POST /check` for
external destinations, and cancels + shows the block/isolate page on a non-allow decision. Closest
to an "agent in the browser"; deploy via MDM/group policy. Keep an allowlist to avoid checking
every internal navigation.

## What the gate does and does not do

- **Does:** stop a user from reaching a known phishing page; hold unknown links in isolation;
  never block a training exercise; give one consistent decision across every enforcement point.
- **Does not:** detect the token theft itself (it acts on the *precursor* — a brand login on the
  wrong domain), and it does not replace phishing-resistant MFA and device-compliant Conditional
  Access (`docs/identity-hardening.md`). A cloaking kit can still defeat a block; that is why the
  unknown and suspicious defaults are isolation, not allow.
