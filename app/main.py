import os
import shutil
import uuid
from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List

from app.elf_analyzer import analyze_so, disassemble_func
from app.translator import translate_arm64_to_vm
from app.builder import generate_virtualized_so

app = FastAPI(title="SO VM Virtualizer Workspace")

# In-memory session-like cache for uploaded SOs
UPLOAD_DIR = "/tmp/so_virtualizer_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Keep track of uploaded SO info
uploaded_files_db = {}
build_outputs_db = {}

@app.get("/", response_class=HTMLResponse)
async def read_index(request: Request):
    template_path = os.path.join(os.path.dirname(__file__), "..", "templates", "index.html")
    with open(template_path, "r") as f:
        return f.read()

@app.post("/api/upload")
async def upload_so(file: UploadFile = File(...)):
    so_id = str(uuid.uuid4())
    filepath = os.path.join(UPLOAD_DIR, f"{so_id}_{file.filename}")

    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        analysis = analyze_so(filepath)
        uploaded_files_db[so_id] = {
            "filepath": filepath,
            "arch": analysis["arch"],
            "exports": analysis["exports"]
        }
        return {
            "so_id": so_id,
            "arch": analysis["arch"],
            "exports": analysis["exports"]
        }
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return {"error": f"Failed to analyze ELF structure: {str(e)}"}

class DisasmRequest(BaseModel):
    so_id: str
    arch: str
    address: int
    size: int

@app.post("/api/disassemble")
async def disassemble_api(req: DisasmRequest):
    if req.so_id not in uploaded_files_db:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    so_info = uploaded_files_db[req.so_id]
    try:
        raw_instructions = disassemble_func(so_info["filepath"], req.arch, req.address, req.size)
        vm_instructions = translate_arm64_to_vm(raw_instructions)
        return {
            "disasm": raw_instructions,
            "vm_code": vm_instructions
        }
    except Exception as e:
        return {"error": f"Disassembly / Translation engine error: {str(e)}"}

class BuildRequest(BaseModel):
    so_id: str
    arch: str
    functions: List[str]

@app.post("/api/build")
async def build_api(req: BuildRequest):
    if req.so_id not in uploaded_files_db:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    so_info = uploaded_files_db[req.so_id]

    # 1. Disassemble and translate all requested functions
    selected_funcs_data = []
    for f_name in req.functions:
        # Find function size and address from analysis
        func_entry = next((x for x in so_info["exports"] if x["name"] == f_name), None)
        if not func_entry:
            continue

        raw_instructions = disassemble_func(so_info["filepath"], req.arch, func_entry["address"], func_entry["size"])
        vm_instructions = translate_arm64_to_vm(raw_instructions)
        selected_funcs_data.append({
            "name": f_name,
            "instructions": vm_instructions
        })

    if not selected_funcs_data:
        return {"error": "No valid functions selected for virtualization."}

    # 2. Invoke builder
    output_so, c_source, err = generate_virtualized_so(req.arch, selected_funcs_data, so_info["filepath"])
    if err:
        return {"error": err, "source_code": c_source}

    build_id = str(uuid.uuid4())
    build_outputs_db[build_id] = output_so

    return {
        "build_id": build_id,
        "source_code": c_source
    }

@app.get("/api/download/{build_id}")
async def download_api(build_id: str):
    if build_id not in build_outputs_db:
        raise HTTPException(status_code=404, detail="Build result not found")

    filepath = build_outputs_db[build_id]
    return FileResponse(filepath, media_type="application/octet-stream", filename="libprotected.so")
