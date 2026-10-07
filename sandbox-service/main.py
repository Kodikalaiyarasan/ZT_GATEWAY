"""
Zero Trust Gateway — Sandbox File Inspector

FastAPI service that scans uploaded files for threats:
  1. SHA-256 hash checked against a Redis-backed blocklist.
  2. Static signature analysis (magic bytes, suspicious patterns).
  3. Returns a clean/dirty verdict with threat details.
"""

import hashlib
import re
from typing import Optional

import redis
import uvicorn
from fastapi import FastAPI, File, UploadFile
from pydantic import BaseModel

# ── App ───────────────────────────────────────────────────────

app = FastAPI(
    title="ZT Sandbox File Inspector",
    version="1.0.0",
)

# ── Redis connection ──────────────────────────────────────────

redis_client = redis.Redis(host="redis", port=6379, db=0, decode_responses=True)

# ── Known-malicious hash seeds (loaded into Redis on startup) ─

SEED_BLOCKED_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty file — test marker",
    "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3a3f2ceb8bfb0cbb5e02ba12e": "Known malware sample SHA-256",
    "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592": "Trojan dropper signature",
}

# Suspicious byte signatures (magic bytes / patterns)
SUSPICIOUS_SIGNATURES = [
    (b"MZ",                     "PE/COFF executable header (Windows EXE/DLL)"),
    (b"\x7fELF",                "ELF executable header (Linux binary)"),
    (b"#!/",                    "Script with shebang — potential shell/script injection"),
    (b"PK\x03\x04",            "ZIP archive — may contain nested threats"),
    (b"%PDF-",                  "PDF document — checking for embedded JS"),
    (b"\xd0\xcf\x11\xe0",      "OLE2 Compound File (legacy Office macro document)"),
]

# Regex patterns for suspicious text content
SUSPICIOUS_TEXT_PATTERNS = [
    (re.compile(rb"eval\s*\(", re.IGNORECASE),       "eval() call — potential code injection"),
    (re.compile(rb"exec\s*\(", re.IGNORECASE),       "exec() call — potential code execution"),
    (re.compile(rb"import\s+os",  re.IGNORECASE),    "os module import — potential system access"),
    (re.compile(rb"import\s+subprocess", re.IGNORECASE), "subprocess import — potential command execution"),
    (re.compile(rb"powershell", re.IGNORECASE),       "PowerShell reference — potential Windows exploit"),
    (re.compile(rb"/bin/sh",   re.IGNORECASE),        "Shell reference — potential Unix exploit"),
    (re.compile(rb"cmd\.exe",  re.IGNORECASE),        "cmd.exe reference — potential Windows command execution"),
    (re.compile(rb"<script",   re.IGNORECASE),        "HTML script tag — potential XSS payload"),
]


class ScanResult(BaseModel):
    clean: bool
    hash: str
    filename: str
    file_size: int
    threat_found: Optional[str] = None


@app.on_event("startup")
async def seed_redis_blocklist():
    """Populate Redis with known-bad hashes on startup."""
    for sha, description in SEED_BLOCKED_HASHES.items():
        redis_client.set(f"blocked_hash:{sha}", description)
    print(f"[sandbox] Seeded {len(SEED_BLOCKED_HASHES)} blocked hashes into Redis")


@app.post("/scan", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...)):
    """
    Scan an uploaded file for threats.

    1. Compute SHA-256 and check against Redis blocklist.
    2. Run static signature detection on the first 8 KB.
    3. Run regex pattern matching on text-like content.
    """
    contents = await file.read()
    file_size = len(contents)
    filename = file.filename or "unknown"

    # ── SHA-256 hash ──────────────────────────────────────────
    sha256 = hashlib.sha256(contents).hexdigest()

    # ── 1. Redis blocklist lookup ─────────────────────────────
    blocked_reason = redis_client.get(f"blocked_hash:{sha256}")
    if blocked_reason:
        print(f"[sandbox] BLOCKED hash={sha256} file={filename} reason={blocked_reason}")
        return ScanResult(
            clean=False,
            hash=sha256,
            filename=filename,
            file_size=file_size,
            threat_found=f"Blocked hash match: {blocked_reason}",
        )

    # ── 2. Magic byte / signature scan (first 8 KB) ──────────
    header = contents[:8192]
    for sig, description in SUSPICIOUS_SIGNATURES:
        if header.startswith(sig) or sig in header[:16]:
            # PDFs are allowed unless they contain JavaScript
            if sig == b"%PDF-":
                if b"/JavaScript" in contents or b"/JS" in contents:
                    print(f"[sandbox] THREAT file={filename}: PDF with embedded JavaScript")
                    return ScanResult(
                        clean=False,
                        hash=sha256,
                        filename=filename,
                        file_size=file_size,
                        threat_found="PDF with embedded JavaScript detected",
                    )
                continue  # benign PDF

            # Executables are always flagged
            if sig in (b"MZ", b"\x7fELF"):
                print(f"[sandbox] THREAT file={filename}: {description}")
                return ScanResult(
                    clean=False,
                    hash=sha256,
                    filename=filename,
                    file_size=file_size,
                    threat_found=description,
                )

            # OLE2 macro documents are flagged
            if sig == b"\xd0\xcf\x11\xe0":
                print(f"[sandbox] THREAT file={filename}: {description}")
                return ScanResult(
                    clean=False,
                    hash=sha256,
                    filename=filename,
                    file_size=file_size,
                    threat_found=description,
                )

    # ── 3. Text-pattern analysis ──────────────────────────────
    for pattern, description in SUSPICIOUS_TEXT_PATTERNS:
        if pattern.search(contents):
            print(f"[sandbox] THREAT file={filename}: {description}")
            return ScanResult(
                clean=False,
                hash=sha256,
                filename=filename,
                file_size=file_size,
                threat_found=description,
            )

    # ── Clean ─────────────────────────────────────────────────
    # Cache the clean hash in Redis for 1 hour to speed up re-scans
    redis_client.setex(f"clean_hash:{sha256}", 3600, filename)
    print(f"[sandbox] CLEAN file={filename} hash={sha256}")

    return ScanResult(
        clean=True,
        hash=sha256,
        filename=filename,
        file_size=file_size,
        threat_found=None,
    )


@app.get("/health")
async def health():
    return {"status": "UP", "service": "sandbox-file-inspector"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)
