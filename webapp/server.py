"""FastAPI app serving the luretrace forensics console.

Run:  uvicorn webapp.server:app --reload
Env:  LURETRACE_SCANS          path to the scans directory (default ./scans)
      LURETRACE_INBOX          job directory the isolated worker drains; when set, /submit
                               queues work there instead of detonating on the console host
      LURETRACE_SUBMIT_MODE    queue | local | off (default: queue if LURETRACE_INBOX is set,
                               else local)
      LURETRACE_CONSOLE_SECRET key for the CSRF token (default: random per process)
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import store


def _build_cfg():
    """A Config for on-demand scans from the console, driven by the same env the console reads."""
    from luretrace.config import Config
    return Config(
        output_dir=str(store.scans_dir()),
        proxy=os.environ.get("LURETRACE_PROXY"),
        allowlist_domains=[d for d in os.environ.get("LURETRACE_ALLOWLIST", "").split(",") if d],
        trusted_login_domains=[d for d in os.environ.get("LURETRACE_TRUSTED_LOGIN", "").split(",") if d],
        rescan_auto=False,  # the console host is not the worker; it keeps no rescan queue
    )


BASE = Path(__file__).parent
app = FastAPI(title="luretrace", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE / "templates"))
templates.env.globals["app_name"] = "luretrace"
templates.env.filters["ftime"] = store.fmt_time

# Artifact filenames the console will serve from inside a scan dir. Nothing else is reachable.
_ARTIFACT = re.compile(r"^(hop_\d+\.(png|html)|chain\.har|report\.json)$")

_SECRET = (os.environ.get("LURETRACE_CONSOLE_SECRET") or secrets.token_hex(32)).encode()

_SECURITY_HEADERS = {
    # Pages show attacker-controlled strings (titles, URLs); never let them run or frame us.
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; script-src 'self'; "
                               "style-src 'self'; object-src 'none'; base-uri 'none'; "
                               "frame-ancestors 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    # Forensics URLs name phishing hosts; never leak them (or scan ids) in Referer.
    "Referrer-Policy": "no-referrer",
}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for key, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    return response


def csrf_token() -> str:
    return hmac.new(_SECRET, b"luretrace-submit-v1", hashlib.sha256).hexdigest()


def _same_origin(request: Request) -> bool:
    """Reject cross-site form posts. Browsers send Origin on POST; fall back to Referer."""
    source = request.headers.get("origin") or request.headers.get("referer")
    if not source:
        return True  # non-browser client; the CSRF token still has to match
    return (urlsplit(source).netloc or "").lower() == (request.headers.get("host") or "").lower()


def _submit_mode() -> str:
    mode = os.environ.get("LURETRACE_SUBMIT_MODE", "").lower()
    if mode in ("queue", "local", "off"):
        return mode
    return "queue" if os.environ.get("LURETRACE_INBOX") else "local"


def _back(**params) -> RedirectResponse:
    return RedirectResponse("/submit?" + urlencode(params), status_code=303)


def render(request: Request, name: str, **ctx) -> HTMLResponse:
    ctx["request"] = request
    ctx["path"] = request.url.path
    ctx["scans_label"] = str(store.scans_dir())
    return templates.TemplateResponse(request, name, ctx)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    rows = store.load_index()
    return render(request, "dashboard.html",
                  stats=store.stats(rows), fails=store.recent_fails(rows), recent=rows[:10])


@app.get("/scans", response_class=HTMLResponse)
def scans(request: Request, status: str = "all"):
    all_rows = store.load_index()
    rows = all_rows if status == "all" else [r for r in all_rows if r["label"] == status]
    return render(request, "scans.html", rows=rows, status=status, counts=store.stats(all_rows))


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, scan_id: str):
    verdict = store.load_scan(scan_id)
    if verdict is None:
        return render(request, "notfound.html", scan_id=scan_id)
    artifacts = {}
    d = store.scans_dir() / scan_id
    if d.is_dir():
        artifacts = {p.name for p in d.iterdir() if _ARTIFACT.match(p.name)}
    return render(request, "scan_detail.html", v=verdict, scan_id=scan_id, artifacts=artifacts)


@app.get("/sources", response_class=HTMLResponse)
def sources(request: Request):
    return render(request, "sources.html")


@app.get("/submit", response_class=HTMLResponse)
def submit_form(request: Request, error: str = "", note: str = ""):
    return render(request, "submit.html", error=error, note=note, csrf=csrf_token(),
                  mode=_submit_mode())


@app.post("/submit")
async def submit(request: Request, url: str = Form(""), csrf: str = Form(""),
                 eml: UploadFile | None = File(None)):
    if not _same_origin(request) or not hmac.compare_digest(csrf, csrf_token()):
        return PlainTextResponse("Forbidden: missing or invalid form token", status_code=403)
    mode = _submit_mode()
    if mode == "off":
        return _back(error="On-demand submission is disabled on this console")
    url = (url or "").strip()
    has_eml = eml is not None and bool(eml.filename)
    if not has_eml and not url:
        return _back(error="enter a URL or choose a .eml file")
    if url and urlsplit(url).scheme.lower() not in ("http", "https"):
        return _back(error="only http(s) links can be submitted")

    if mode == "queue":
        from luretrace import inbox
        inbox_dir = os.environ["LURETRACE_INBOX"]
        if has_eml:
            inbox.enqueue_eml(inbox_dir, await eml.read())
        else:
            inbox.enqueue_url(inbox_dir, url, source="console")
        return _back(note="Queued for the isolated worker. It will appear in Scans when done.")

    try:
        from luretrace.pipeline import scan_message, scan_url
    except Exception:
        return _back(error="engine not installed on this host")
    cfg = _build_cfg()
    try:
        if has_eml:
            verdicts = await scan_message(await eml.read(), cfg)
        else:
            verdicts = [await scan_url(url, cfg)]
    except Exception as exc:  # e.g. no browser installed on this host
        return _back(error="scan failed: " + str(exc).splitlines()[0][:160])

    scanned = [v for v in verdicts if v.artifacts_dir]
    if scanned:
        return RedirectResponse(f"/scans/{Path(scanned[0].artifacts_dir).name}", status_code=303)
    labels = ", ".join(sorted({v.label for v in verdicts})) or "nothing"
    return _back(note=f"No detonation ({labels}). Private or allowlisted links are skipped.")


@app.get("/scans/{scan_id}/artifact/{name}")
def artifact(scan_id: str, name: str):
    if not _ARTIFACT.match(name) or not store.valid_scan_id(scan_id):
        return PlainTextResponse("Not found", status_code=404)
    path = (store.scans_dir() / scan_id / name).resolve()
    root = store.scans_dir().resolve()
    if root not in path.parents or not path.is_file():
        return PlainTextResponse("Not found", status_code=404)
    if name.endswith(".png"):
        return FileResponse(path)  # screenshots render inline
    # Captured HTML/HAR are live hostile content: never render, force download.
    return FileResponse(path, media_type="application/octet-stream", filename=f"{scan_id}-{name}")


@app.get("/healthz", response_class=PlainTextResponse)
def healthz():
    return "ok"


@app.get("/favicon.ico")
def favicon():
    return RedirectResponse("/static/favicon.svg")
