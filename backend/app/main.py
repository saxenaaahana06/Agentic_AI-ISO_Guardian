
import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from services.iso_analyzer import analyze_iso

app = FastAPI(
    title="ISO Guardian",
    description="Windows 11 ISO integrity and structural analysis",
    version="1.0.0",
)

MAX_UPLOAD_SIZE = 20 * 1024 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024


@app.get("/")
def home():
    return {
        "project": "ISO Guardian",
        "status": "running",
        "message": "Windows ISO analysis backend is ready",
    }


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "ISO Guardian Backend",
    }


@app.post("/api/iso/analyze")
async def upload_and_analyze_iso(
    file: UploadFile = File(...),
    expected_sha256: str = Form(default=""),
):
    filename = Path(file.filename or "upload.iso").name

    if Path(filename).suffix.lower() != ".iso":
        raise HTTPException(
            status_code=400,
            detail="Please upload a Windows ISO file with the .iso extension.",
        )

    temp_path = None
    total_size = 0

    try:
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".iso"
        ) as temp:
            temp_path = temp.name

            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break

                total_size += len(chunk)
                if total_size > MAX_UPLOAD_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File exceeds the 20 GB upload limit.",
                    )

                temp.write(chunk)

        if total_size == 0:
            raise HTTPException(
                status_code=400,
                detail="The uploaded file is empty.",
            )

        result = analyze_iso(
            temp_path,
            expected_sha256=expected_sha256 or None,
        )
        result["filename"] = filename
        return result

    finally:
        await file.close()
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
