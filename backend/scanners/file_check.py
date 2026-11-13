"""File integrity: streamed SHA-256, size, magic-byte type, extension sanity.
Files are read in memory chunks only; nothing is written to disk or executed.
A hash proves integrity of content, it does NOT detect malware."""
import hashlib
import io
import re

from werkzeug.utils import secure_filename

import config
from ..messages import build, verdict
from .url_scanner import ScanError

SIGS = [(b"%PDF", "pdf", "PDF document"), (b"\x89PNG\r\n\x1a\n", "png", "PNG image"),
        (b"\xff\xd8\xff", "jpg", "JPEG image"), (b"GIF8", "gif", "GIF image"),
        (b"PK\x03\x04", "zip", "ZIP container (ZIP/DOCX/XLSX/PPTX/JAR/APK)"),
        (b"Rar!", "rar", "RAR archive"), (b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
        (b"MZ", "exe", "Windows executable (PE)"), (b"\x7fELF", "elf", "Linux executable (ELF)"),
        (b"\x1f\x8b", "gz", "GZIP archive"), (b"SQLite format 3\x00", "sqlite", "SQLite database"),
        (b"\xd0\xcf\x11\xe0", "ole", "Legacy Office document (OLE)")]
EXPECT = {"pdf": {"pdf"}, "png": {"png"}, "jpg": {"jpg"}, "jpeg": {"jpg"}, "gif": {"gif"},
          "zip": {"zip"}, "docx": {"zip"}, "xlsx": {"zip"}, "pptx": {"zip"}, "rar": {"rar"},
          "7z": {"7z"}, "gz": {"gz"}, "txt": {"text"}, "csv": {"text"}, "json": {"text"},
          "doc": {"ole"}, "xls": {"ole"}, "ppt": {"ole"}, "exe": {"exe"}, "dll": {"exe"}}
EXEC_KINDS = {"exe", "elf"}
RISKY_EXT = {"exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "jar", "msi", "scr", "com", "lnk", "hta", "apk", "sh"}
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\.(exe|scr|bat|cmd|js|vbs|ps1|com|lnk|hta)$", re.I)
EICAR_MARK = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"   # harmless industry test pattern
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def valid_hash(text):
    t = (text or "").strip().lower()
    return t if HEX64.match(t) else None


def _kind(head):
    for sig, code, label in SIGS:
        if head.startswith(sig):
            return code, label
    try:
        head.decode("utf-8", errors="strict")
        if b"\x00" not in head:
            return "text", "Plain text"
    except UnicodeDecodeError as e:
        if e.start >= len(head) - 3 and b"\x00" not in head:   # cut mid-character
            return "text", "Plain text"
    return "unknown", "Unknown / binary data"


def analyze(storage):
    """storage: werkzeug FileStorage. Returns result dict."""
    name = secure_filename(storage.filename or "") or "file"
    h, size, head = hashlib.sha256(), 0, b""
    limit = config.MAX_FILE_MB * 1024 * 1024
    while True:
        chunk = storage.stream.read(1024 * 1024)
        if not chunk:
            break
        if not head:
            head = chunk[:4096]
        size += len(chunk)
        if size > limit:
            raise ScanError("file_too_large")
        h.update(chunk)
    if size == 0:
        raise ScanError("empty_file")

    kind, label = _kind(head)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    findings = []
    eicar = EICAR_MARK in head[:512]
    if eicar:
        findings.append(build("eicar_test", 60))
    if DOUBLE_EXT.search(name):
        findings.append(build("double_ext", 40, ext=ext))
    if kind in EXEC_KINDS and ext not in RISKY_EXT and ext not in ("",):
        findings.append(build("disguised_exe", 60, ext=ext))
    elif ext in EXPECT and kind not in EXPECT[ext]:
        findings.append(build("type_mismatch", 25, ext=ext, kind=label))
    if ext in RISKY_EXT:
        findings.append(build("risky_ext", 20, ext=ext))
    score = min(100, sum(f["points"] for f in findings))
    findings.sort(key=lambda f: -f["points"])
    return {"name": name[:120], "size": size, "kind": label, "sha256": h.hexdigest(), "eicar": eicar,
            "score": score, "verdict": verdict(score), "findings": findings}


class _Mem:
    """Minimal in-memory stand-in for an uploaded file (used by the lab with synthetic samples)."""
    def __init__(self, name, data):
        self.filename, self.stream = name, io.BytesIO(data)


def analyze_bytes(name, data):
    return analyze(_Mem(name, data))
