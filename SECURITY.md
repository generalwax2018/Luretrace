# Security policy

## Reporting a vulnerability in luretrace

If you find a security issue in luretrace itself, please report it privately. Do **not** open a
public issue for anything exploitable.

- Use GitHub's **private vulnerability reporting** (Security tab → Report a vulnerability), or
- email the maintainer listed on the repository profile.

Please include what you found, how to reproduce it, and the impact. Expect an acknowledgement
within a few days. There is no bug-bounty program; this is a community project.

## Scope

In scope: issues in luretrace's own code — for example the SSRF guard being bypassable, the
artifact route serving files outside a scan directory, the gate returning `allow` when it should
not, or the detonation worker reaching a network it should not.

Out of scope: phishing pages that evade detection. luretrace is a heuristic tool and misses are
expected, not vulnerabilities. Report detection gaps as normal issues or PRs.

## Operating luretrace safely

luretrace **opens live, potentially hostile web pages on purpose**. Running it carries real risk,
and most of it is on the operator, not the code:

- Run detonation workers on an isolated host/segment with its own internet egress and no route to
  corporate networks or cloud metadata endpoints. The built-in `netguard` is defence in depth, not
  the boundary. See [`docs/deployment.md`](docs/deployment.md).
- Treat everything under the scans directory (captured HTML, downloads) as **live malware**.
- The web console and the gate have **no authentication of their own** by design — front them with
  your SSO / reverse proxy and keep them on internal networks.
- The honeytoken feature performs active deception. It is off by default; read the warning in the
  README before enabling it, and ensure you are authorised and compliant with local law.

## Supported versions

This is pre-1.0 **beta** software (`0.1.0b1`). Only the latest `main` is supported, interfaces may
change, and it is not production-validated. Pin a commit if you deploy it, and pilot in a lab.
