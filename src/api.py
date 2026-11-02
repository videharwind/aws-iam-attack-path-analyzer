"""Local single-user tool, no authentication.
Run with: uvicorn api:app --app-dir src --host 127.0.0.1 --port 8000
"""

from pathlib import Path
import re
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from snapshot import load_snapshot, snapshot_from_dict
from analysis import (
    build_attack_graph,
    summarize,
    list_identities,
    reachable_report,
)
from graph_export import graph_to_json

ROOT = Path(__file__).resolve().parent.parent
SNAP_DIR = ROOT / "snapshots"
FRONTEND_DIR = ROOT / "frontend"

app = FastAPI(title="IAM Attack Path Analyzer")

if FRONTEND_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


class AppState:
    def __init__(self):
        self.inventory = None
        self.permission_map = None
        self.graph = None
        self.meta = None
        self.snapshot_name = None

    def is_loaded(self):
        return self.graph is not None

    def reset(self):
        self.inventory = None
        self.permission_map = None
        self.graph = None
        self.meta = None
        self.snapshot_name = None


state = AppState()


def reset_state():
    state.reset()


def require_snapshot():
    if not state.is_loaded():
        raise HTTPException(status_code=409, detail="No snapshot loaded")


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/snapshots")
def get_snapshots():
    if not SNAP_DIR.is_dir():
        return {"snapshots": []}
    files = []
    for f in sorted(SNAP_DIR.glob("*.json")):
        if f.is_file():
            files.append({"name": f.name, "size": f.stat().st_size})
    return {"snapshots": files}


@app.post("/api/snapshots/load")
def load_snapshot_endpoint(body: dict):
    name = body.get("name")
    if not name or not isinstance(name, str):
        raise HTTPException(status_code=400, detail="Filename must be provided")

    if not re.match(r"^[A-Za-z0-9._-]+\.json$", name) or ".." in name:
        raise HTTPException(status_code=400, detail=f"Invalid snapshot filename: '{name}'")

    file_path = SNAP_DIR / name
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail=f"Snapshot '{name}' not found")

    try:
        inv, pm, meta = load_snapshot(file_path)
        graph = build_attack_graph(inv, pm)
        state.inventory = inv
        state.permission_map = pm
        state.graph = graph
        state.meta = meta
        state.snapshot_name = name
        return {"loaded": name, "meta": meta}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/snapshots/upload")
def upload_snapshot(request: Request, body: dict):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Payload too large (>10MB)")

    try:
        inv, pm, meta = snapshot_from_dict(body)
        graph = build_attack_graph(inv, pm)
        state.inventory = inv
        state.permission_map = pm
        state.graph = graph
        state.meta = meta
        state.snapshot_name = "(uploaded)"
        return {"loaded": "(uploaded)", "meta": meta}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/summary")
def get_summary():
    require_snapshot()
    data = summarize(state.inventory, state.graph)
    data["meta"] = state.meta
    data["snapshot_name"] = state.snapshot_name
    return data


@app.get("/api/identities")
def get_identities():
    require_snapshot()
    return {"identities": list_identities(state.graph)}


@app.get("/api/reachable")
def get_reachable(source: str, max_hops: int = Query(None, ge=0)):
    require_snapshot()
    try:
        results = reachable_report(state.graph, source_arn=source, max_hops=max_hops)
        return {"source": source, "max_hops": max_hops, "results": results}
    except ValueError as e:
        # Unknown source or invalid node in view -> 404
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/graph/full")
def get_graph_full():
    require_snapshot()
    return graph_to_json(state.graph, mode="full")


@app.get("/api/graph/attack")
def get_graph_attack():
    require_snapshot()
    return graph_to_json(state.graph, mode="attack")


@app.get("/")
def serve_index():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.is_file():
        return FileResponse(index_file)
    raise HTTPException(status_code=404, detail="index.html not found")


@app.get("/how-to-use")
def serve_howto():
    howto_file = FRONTEND_DIR / "howto.html"
    if howto_file.is_file():
        return FileResponse(howto_file)
    raise HTTPException(status_code=404, detail="howto.html not found")


@app.get("/about")
def serve_about():
    about_file = FRONTEND_DIR / "about.html"
    if about_file.is_file():
        return FileResponse(about_file)
    raise HTTPException(status_code=404, detail="about.html not found")

