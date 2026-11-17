"""FastAPI app serving the luretrace forensics console.

Run:  uvicorn webapp.server:app --reload
Env:  LURETRACE_SCANS   path to the scans directory (default ./scans)
"""
from __future__ import annotations

import re
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import store


def _build_cfg():
    """A Config for on-demand scans from the console, driven by the same env the console reads."""
    import os

    from luretrace.config import Config
    return Config(
        output_dir=str(store.scans_dir()),
        proxy=os.environ.get("LURETRACE_PROXY"),
        allowlist_domains=[d for d in os.environ.get("LURETRACE_ALLOWLIST", "").split(",") if d],
        trusted_login_domains=[d for d in os.environ.get("LURETRACE_TRUSTED_LOGIN", "").split(",") if d],
    )

BASE = Path(__file__).parent
app = FastAPI(title="luretrace", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE / "templates"))
templates.env.globals["app_name"] = "luretrace"
templates.env.filters["ftime"] = store.fmt_time

# Artifact filenames the console will serve from inside a scan dir. Nothing else is reachable.
_ARTIFACT = re.compile(r"^(hop_\d+\.(png|html)|chain\.har|report\.json)$")


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
    rows = store.load_index()
    if status != "all":
        rows = [r for r in rows if r["label"] == status]
    return render(request, "scans.html", rows=rows, status=status,
                  counts=store.stats(store.load_index()))


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
    return render(request, "submit.html", error=error, note=note)


@app.post("/submit")
async def submit(request: Request, url: str = Form(""), eml: UploadFile | None = File(None)):
    url = (url or "").strip()
    try:
        from luretrace.pipeline import scan_message, scan_url
    except Exception:
        return RedirectResponse("/submit?error=engine+not+installed+on+this+host", status_code=303)

    cfg = _build_cfg()
    try:
        if eml is not None and eml.filename:
            verdicts = await scan_message(await eml.read(), cfg)
        elif url:
            verdicts = [await scan_url(url, cfg)]
        else:
            return RedirectResponse("/submit?error=enter+a+URL+or+choose+a+.eml+file", status_code=303)
    except Exception as exc:  # e.g. no browser installed on this host
        msg = str(exc).splitlines()[0][:160].replace(" ", "+")
        return RedirectResponse(f"/submit?error=scan+failed:+{msg}", status_code=303)

    scanned = [v for v in verdicts if v.artifacts_dir]
    if scanned:
        from pathlib import Path
        return RedirectResponse(f"/scans/{Path(scanned[0].artifacts_dir).name}", status_code=303)
    labels = ", ".join(sorted({v.label for v in verdicts})) or "nothing"
    return RedirectResponse(f"/submit?note=No+detonation+({labels}).+Private+or+allowlisted+links+are+skipped.",
                            status_code=303)


@app.get("/scans/{scan_id}/artifact/{name}")
def artifact(scan_id: str, name: str):
    if not _ARTIFACT.match(name) or "/" in scan_id or "\\" in scan_id or ".." in scan_id:
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
