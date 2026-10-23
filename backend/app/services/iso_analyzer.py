
import hashlib
import re
from pathlib import Path

import pycdlib

CHUNK_SIZE = 1024 * 1024
MAX_ISO_SIZE = 20 * 1024 * 1024 * 1024
SECTOR_SIZE = 2048


def calculate_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while True:
            chunk = file.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def normalize_iso_path(value: str) -> str:
    value = value.replace("\\", "/").strip("/").upper()
    return re.sub(r";\d+$", "", value)


def analyze_iso(file_path: str, expected_sha256: str | None = None) -> dict:
    path = Path(file_path)

    if not path.is_file():
        return {"status": "error", "message": "File not found"}

    size = path.stat().st_size

    if size == 0:
        return {"status": "invalid", "message": "File is empty"}

    if size > MAX_ISO_SIZE:
        return {"status": "rejected", "message": "File exceeds 20 GB"}

    sha256 = calculate_sha256(path)

    with path.open("rb") as file:
        header = file.read(64 * SECTOR_SIZE)

    # Look for ISO 9660 descriptors in sectors 16–63.
    iso9660_detected = False
    for sector in range(16, 64):
        start = sector * SECTOR_SIZE
        if len(header) >= start + 6:
            if header[start + 1:start + 6] == b"CD001":
                iso9660_detected = True
                break

    # Look for UDF volume recognition identifiers.
    udf_detected = False
    for sector in range(16, 64):
        start = sector * SECTOR_SIZE
        identifier = header[start + 1:start + 6]
        if identifier in (b"NSR02", b"NSR03"):
            udf_detected = True
            break

    entries = set()
    directory_inspection = "not_available"
    inspection_error = None
    iso = pycdlib.PyCdlib()

    try:
        iso.open(str(path))
        for dirpath, dirnames, filenames in iso.walk(iso_path="/"):
            base = dirpath.strip("/")
            for name in dirnames + filenames:
                full_path = f"{base}/{name}" if base else name
                entries.add(normalize_iso_path(full_path))
        directory_inspection = "completed"
    except Exception as exc:
        inspection_error = type(exc).__name__
        directory_inspection = "not_supported_or_unreadable"
    finally:
        try:
            iso.close()
        except Exception:
            pass

    expected_files = {
        "SETUP.EXE": "Windows Setup executable",
        "BOOTMGR": "Legacy boot manager",
        "BOOT/ETFSBOOT.COM": "Legacy boot image",
        "EFI/BOOT/BOOTX64.EFI": "UEFI boot application",
        "SOURCES/BOOT.WIM": "Windows PE setup image",
    }

    indicators = {}
    if directory_inspection == "completed":
        for iso_path, description in expected_files.items():
            indicators[iso_path] = {
                "description": description,
                "found": iso_path in entries,
            }

        install_images = [
            item for item in entries
            if item in ("SOURCES/INSTALL.WIM", "SOURCES/INSTALL.ESD")
        ]
        indicators["WINDOWS_INSTALL_IMAGE"] = {
            "description": "Windows installation image",
            "found": bool(install_images),
            "matching_files": install_images,
        }

    checksum_status = "not_provided"
    if expected_sha256:
        expected_sha256 = expected_sha256.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            checksum_status = "invalid_reference"
        else:
            checksum_status = (
                "match" if sha256 == expected_sha256 else "mismatch"
            )

    warnings = []
    if not iso9660_detected and not udf_detected:
        warnings.append(
            "No ISO 9660 or UDF recognition identifier detected in the checked sectors."
        )
    if directory_inspection != "completed":
        warnings.append(
            "Directory listing could not be inspected as ISO 9660. "
            "This alone does not mean the ISO is invalid."
        )
    if checksum_status == "mismatch":
        warnings.append("SHA-256 does not match the supplied reference.")
    if checksum_status == "not_provided":
        warnings.append("No trusted reference SHA-256 was provided.")

    if directory_inspection == "completed":
        required = [
            "SETUP.EXE",
            "SOURCES/BOOT.WIM",
            "WINDOWS_INSTALL_IMAGE",
        ]
        missing = [
            item for item in required
            if not (
                indicators.get(item, {}).get("found", False)
                if item != "WINDOWS_INSTALL_IMAGE"
                else indicators.get(item, {}).get("found", False)
            )
        ]
        if missing:
            warnings.append(
                "Some expected Windows setup indicators were not found: "
                + ", ".join(missing)
            )

    return {
        "status": "analyzed",
        "filename": path.name,
        "size_bytes": size,
        "size_mb": round(size / (1024 * 1024), 2),
        "sha256": sha256,
        "checksum_reference_status": checksum_status,
        "iso9660_detected": iso9660_detected,
        "udf_identifier_detected": udf_detected,
        "directory_inspection": directory_inspection,
        "inspection_error": inspection_error,
        "windows_indicators": indicators,
        "warnings": warnings,
        "safety_verdict": "NOT DETERMINED",
        "note": (
            "Structural indicators do not prove safety or authenticity. "
            "Compare the hash with a trusted reference for the exact ISO."
        ),
    }
