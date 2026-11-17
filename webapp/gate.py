"""Click-time gate service. Enforcement-agnostic: any point in the click path calls it.

Run:  uvicorn webapp.gate:gate_app --port 8090
Env:  LURETRACE_SCANS            scans dir the verdict cache reads
      LURETRACE_UNKNOWN_ACTION   isolate (default) | block | allow | scan
      LURETRACE_SUSPICIOUS_ACTION isolate (default) | block | allow
      LURETRACE_SIM_ACTION       allow (default) | isolate
      LURETRACE_ALLOWLIST        comma-separated domains never blocked
      LURETRACE_SIM_DOMAINS      extra phishing-simulation domains
      LURETRACE_ISOLATION_URL    RBI base; the gate sends isolate decisions here as ?url=<target>

Endpoints:
  POST /check   {"url": "...", "headers": {...}}  -> decision JSON   (for inline/extension)
  GET  /go?u=<url>                                 -> redirect/block/isolate (for a link-rewrite service)
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .gate_core import Policy, decide

BASE = Path(__file__).parent
gate_app = FastAPI(title="luretrace gate", docs_url=None, redoc_url=None)
gate_app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE / "templates"))
templates.env.globals["app_name"] = "luretrace"

POLICY = Policy.from_env()


@gate_app.post("/check")
async def check(request: Request):
    body = await request.json()
    url = (body.get("url") or "").strip()
    if not url:
        return JSONResponse({"action": "block", "reason": "no_url"}, status_code=400)
    d = decide(url, POLICY, headers=body.get("headers"))
    return d.to_dict()


@gate_app.get("/go")
def go(request: Request, u: str = ""):
    if not u:
        return HTMLResponse("missing u", status_code=400)
    d = decide(u, POLICY)
    if d.action == "allow":
        return RedirectResponse(d.url, status_code=302)
    if d.action == "isolate" and POLICY.isolation_url:
        return RedirectResponse(f"{POLICY.isolation_url}?url={quote(d.url, safe='')}", status_code=302)
    page = "block.html" if d.action == "block" else "isolate.html"
    return templates.TemplateResponse(request, page, {"request": request, "d": d},
                                      status_code=200)


@gate_app.get("/healthz")
def healthz():
    return {"ok": True, "policy": POLICY.__dict__}
