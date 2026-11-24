"""Pull URLs out of an email message: bodies, HTML/SVG/PDF/calendar attachments, QR codes."""
from __future__ import annotations

import base64
import binascii
import email
import re
from email import policy
from email.utils import getaddresses
from html.parser import HTMLParser

URL_RE = re.compile(r"""(?i)\b(?:https?|hxxps?)://[^\s<>"'\)\]\\`]+""")
TRAILING = ".,;:!?>"
_META_URL = re.compile(r"(?i)\burl\s*=\s*(.+)$")
# Base64 blobs long enough to hide a URL (HTML smuggling: atob("aHR0cHM6Ly9...")).
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_PDF_URI = re.compile(rb"/URI\s*\((.*?)(?<!\\)\)", re.S)

# Attachments that carry live markup or script and are routinely used to deliver lures.
MARKUP_EXT = (".htm", ".html", ".shtml", ".xhtml", ".svg", ".mht", ".mhtml")
IMAGE_TYPES = ("image/png", "image/jpeg", "image/gif", "image/bmp", "image/webp")
_NAMESPACE_PREFIXES = (
    "http://www.w3.org/", "https://www.w3.org/", "http://ns.adobe.com/", "http://purl.org/",
    "http://schemas.microsoft.com/", "http://schemas.openxmlformats.org/",
    "http://creativecommons.org/ns", "http://inkscape.sourceforge.net/",
    "http://www.inkscape.org/", "http://sodipodi.sourceforge.net/",
)


def refang(url: str) -> str:
    url = re.sub(r"(?i)^hxxp", "http", url.strip())
    url = url.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[://]", "://")
    return url


class _HrefParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if value and key in ("href", "xlink:href", "src", "action", "formaction") and tag in (
                "a", "area", "form", "iframe", "button", "meta"
            ):
                self.urls.append(value)
            if tag == "meta" and key == "content" and value:
                # Keep the URL's case: paths and tokens are case-sensitive.
                m = _META_URL.search(value)
                if m:
                    self.urls.append(m.group(1).strip(" '\""))

    def handle_data(self, data):
        self.text.append(data)


def urls_from_html(html: str) -> list[str]:
    parser = _HrefParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.urls + urls_from_text(" ".join(parser.text))


def urls_from_text(text: str) -> list[str]:
    return [m.group(0).rstrip(TRAILING) for m in URL_RE.finditer(refang_text(text))]


def refang_text(text: str) -> str:
    return text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def urls_from_base64(text: str) -> list[str]:
    """URLs hidden in base64 strings inside script (a common HTML-smuggling trick)."""
    found: list[str] = []
    for token in _B64_TOKEN.findall(text):
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(token + "=" * (-len(token) % 4)).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            found += urls_from_text(decoded)
            break
    return found


def urls_from_markup_attachment(source: str) -> list[str]:
    """HTML/SVG attachments: anchors, plus URLs in script source and base64 blobs."""
    return urls_from_html(source) + urls_from_text(source) + urls_from_base64(source)


def urls_from_pdf(data: bytes) -> list[str]:
    """Link annotations from a PDF. Uses pypdf when installed, else a raw /URI scan."""
    urls: list[str] = []
    try:
        import io

        from pypdf import PdfReader

        for page in PdfReader(io.BytesIO(data)).pages:
            annots = page.get("/Annots")
            for annot in (annots.get_object() if annots is not None else []):
                action = annot.get_object().get("/A")
                action = action.get_object() if action is not None else {}
                uri = action.get("/URI")
                if uri:
                    urls.append(str(uri))
    except Exception:
        urls += [m.decode("latin-1").replace("\\)", ")") for m in _PDF_URI.findall(data)]
    return urls


def urls_from_image(data: bytes) -> list[str]:
    """Decode QR codes in an image (quishing). Needs the optional [attachments] extra."""
    try:
        import io

        import zxingcpp
        from PIL import Image
    except ImportError:
        return []
    try:
        image = Image.open(io.BytesIO(data))
        image.load()
        results = zxingcpp.read_barcodes(image)
    except Exception:
        return []
    out: list[str] = []
    for r in results:
        out += urls_from_text(r.text) or ([r.text] if r.text.lower().startswith("http") else [])
    return out


def qr_available() -> bool:
    try:
        import PIL  # noqa: F401
        import zxingcpp  # noqa: F401
    except ImportError:
        return False
    return True


def _text_of(part) -> str:
    try:
        body = part.get_content()
    except Exception:
        body = part.get_payload(decode=True) or b""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    return body if isinstance(body, str) else str(body)


def _bytes_of(part) -> bytes:
    try:
        return part.get_payload(decode=True) or b""
    except Exception:
        return b""


def extract_urls(raw: bytes, scan_attachments: bool = True,
                 max_attachment_bytes: int = 10_000_000) -> tuple[dict, list[str]]:
    """Return (message metadata, de-duplicated http(s) URLs) from raw RFC 822 bytes.

    meta["origins"] maps each URL to where it was found: "body", "attachment:<name>",
    or "qr:<name>". meta["recipients"] lists the To/Cc addresses.
    """
    msg = email.message_from_bytes(raw, policy=policy.default)
    found: list[tuple[str, str]] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = (part.get_filename() or "").strip()
        is_attachment = part.get_content_disposition() == "attachment" or bool(filename)
        name = filename or ctype

        if ctype in ("text/html", "text/plain") and not is_attachment:
            body = _text_of(part)
            urls = urls_from_html(body) if ctype == "text/html" else urls_from_text(body)
            found += [(u, "body") for u in urls]
            continue
        if not scan_attachments:
            if ctype == "text/html":  # previous behaviour: HTML parts were always read
                found += [(u, f"attachment:{name}") for u in urls_from_html(_text_of(part))]
            continue

        data = _bytes_of(part)
        if len(data) > max_attachment_bytes:
            continue
        lower = filename.lower()
        if ctype in ("text/html", "image/svg+xml", "application/xhtml+xml") or \
                lower.endswith(MARKUP_EXT):
            source = data.decode("utf-8", "replace")
            found += [(u, f"attachment:{name}") for u in urls_from_markup_attachment(source)]
        elif ctype == "text/calendar" or lower.endswith(".ics"):
            found += [(u, f"attachment:{name}") for u in urls_from_text(data.decode("utf-8", "replace"))]
        elif ctype == "application/pdf" or lower.endswith(".pdf"):
            found += [(u, f"attachment:{name}") for u in urls_from_pdf(data)]
        elif ctype in IMAGE_TYPES:
            # Inline (cid:) images count too: QR lures are usually embedded in the body.
            found += [(u, f"qr:{name}") for u in urls_from_image(data)]
        elif ctype == "text/plain":
            found += [(u, f"attachment:{name}") for u in urls_from_text(data.decode("utf-8", "replace"))]

    seen, urls, origins = set(), [], {}
    for u, origin in found:
        u = refang(u)
        if not u.lower().startswith(("http://", "https://")) or u in seen:
            continue
        if u.lower().startswith(_NAMESPACE_PREFIXES):  # XML namespaces in SVG/HTML source
            continue
        seen.add(u)
        urls.append(u)
        origins[u] = origin
    recipients = [addr.lower() for _, addr in getaddresses(
        [str(v) for v in (msg.get_all("To") or []) + (msg.get_all("Cc") or [])]) if "@" in addr]
    meta = {
        "message_id": str(msg.get("Message-ID", "")).strip(),
        "subject": str(msg.get("Subject", "")),
        "from": str(msg.get("From", "")),
        "recipients": recipients,
        "origins": origins,
    }
    return meta, urls
