
import hashlib
import os
from pathlib import Path

MAX_ISO_SIZE = 20 * 1024 * 1024 * 1024  # 20 GB
CHUNK_SIZE = 1024 * 1024  # 1 MB


def analyze_iso(file_path: str) -> dict:
    path = Path(file_path)

    if not path.exists() or not path.is_file():
        return {"status": "error", "message": "File not found"}

    size = os.path.getsize(path)

    if size == 0:
        return {"status": "invalid", "message": "File is empty", "size_bytes": 0}

    if size > MAX_ISO_SIZE:
        return {
            "status": "rejected",
            "message": "File exceeds the 20 GB analysis limit",
            "size_bytes": size,
        }

    sha256 = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(CHUNK_SIZE):
            sha256.update(chunk)

    with path.open("rb") as file:
        header = file.read(32776)

    # ISO 9660 primary volume descriptor begins at byte 32768.
    is_iso9660 = (
        len(header) >= 32774
        and header[32769:32774] == b"CD001"
        and header[32768] == 1
    )

    return {
        "status": "analyzed",
        "filename": path.name,
        "size_bytes": size,
        "size_mb": round(size / (1024 * 1024), 2),
        "sha256": sha256.hexdigest(),
        "iso9660_signature_detected": is_iso9660,
        "message": (
            "ISO 9660 signature detected"
            if is_iso9660
            else "ISO 9660 signature not detected; further format checks are needed"
        ),
        "checksum_verified": False,
        "note": "The SHA-256 hash is calculated, not verified against a trusted reference.",
    }
