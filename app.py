import os
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request, send_file

BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "1800"))

app = Flask(__name__)

tasks: dict[str, dict] = {}
tasks_lock = threading.Lock()

pending: list[str] = []
pending_cv = threading.Condition()
current_tid: str | None = None


def enqueue(tid: str) -> None:
    with pending_cv:
        pending.append(tid)
        pending_cv.notify()


def promote(tid: str) -> bool:
    with pending_cv:
        if tid in pending:
            pending.remove(tid)
            pending.insert(0, tid)
            return True
        return False


def task_view(t: dict) -> dict:
    return {
        "id": t["id"],
        "domain": t["domain"],
        "status": t["status"],
        "created_at": t["created_at"],
        "started_at": t["started_at"],
        "finished_at": t["finished_at"],
        "count": t["count"],
        "error": t["error"],
    }


def make_task(domain: str) -> dict:
    tid = uuid.uuid4().hex[:12]
    task = {
        "id": tid,
        "domain": domain,
        "status": "queued",
        "created_at": time.time(),
        "started_at": None,
        "finished_at": None,
        "count": 0,
        "error": None,
        "output_file": str(RESULTS_DIR / f"{tid}_{domain}.txt"),
    }
    with tasks_lock:
        tasks[tid] = task
    return task


def run_scan(task: dict) -> None:
    task["status"] = "running"
    task["started_at"] = time.time()
    output_file = task["output_file"]
    try:
        proc = subprocess.run(
            ["subfinder", "-d", task["domain"], "-o", output_file, "-silent"],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
        )
        if proc.returncode != 0:
            task["status"] = "failed"
            task["error"] = (proc.stderr or proc.stdout or "subfinder failed").strip()[:1000]
            return
        if os.path.exists(output_file):
            with open(output_file) as f:
                lines = [ln.strip() for ln in f if ln.strip()]
            task["count"] = len(lines)
        task["status"] = "done"
    except FileNotFoundError:
        task["status"] = "failed"
        task["error"] = "subfinder binary not found in PATH"
    except subprocess.TimeoutExpired:
        task["status"] = "failed"
        task["error"] = f"scan timeout after {SCAN_TIMEOUT}s"
    except Exception as e:
        task["status"] = "failed"
        task["error"] = str(e)
    finally:
        task["finished_at"] = time.time()


def worker() -> None:
    global current_tid
    while True:
        with pending_cv:
            while not pending:
                pending_cv.wait()
            tid = pending.pop(0)
            current_tid = tid
        try:
            with tasks_lock:
                task = tasks.get(tid)
            if task:
                run_scan(task)
        finally:
            with pending_cv:
                current_tid = None


threading.Thread(target=worker, daemon=True).start()


@app.route("/")
def index():
    return render_template("index.html")


def parse_domains(raw) -> list[str]:
    if isinstance(raw, list):
        items = raw
    else:
        items = re.split(r"[\s,;]+", str(raw or ""))
    seen, out = set(), []
    for item in items:
        d = item.strip().lower().lstrip("*.")
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


@app.post("/api/scan")
def api_scan():
    data = request.get_json(silent=True) or request.form
    raw = data.get("domains") if "domains" in data else data.get("domain")
    domains = parse_domains(raw)
    if not domains:
        return jsonify({"error": "no domain provided"}), 400

    accepted, rejected = [], []
    for d in domains:
        if DOMAIN_RE.match(d):
            task = make_task(d)
            enqueue(task["id"])
            accepted.append(task_view(task))
        else:
            rejected.append(d)
    if not accepted:
        return jsonify({"error": "invalid domain", "rejected": rejected}), 400
    return jsonify({"accepted": accepted, "rejected": rejected}), 201


@app.get("/api/tasks")
def api_tasks():
    with tasks_lock:
        items = sorted(tasks.values(), key=lambda t: t["created_at"], reverse=True)
    with pending_cv:
        order = list(pending)
        running_id = current_tid
    pos = {tid: i + 1 for i, tid in enumerate(order)}

    counts = {"queued": 0, "running": 0, "done": 0, "failed": 0}
    current_domain = None
    for t in items:
        counts[t["status"]] = counts.get(t["status"], 0) + 1
        if t["id"] == running_id:
            current_domain = t["domain"]

    summary = {
        "total": len(items),
        "queued": counts["queued"],
        "running": counts["running"],
        "done": counts["done"],
        "failed": counts["failed"],
        "finished": counts["done"] + counts["failed"],
        "current_domain": current_domain,
    }

    out = []
    for t in items:
        v = task_view(t)
        if t["status"] == "queued":
            v["position"] = pos.get(t["id"])
        out.append(v)
    return jsonify({"summary": summary, "tasks": out})


@app.post("/api/tasks/<tid>/promote")
def api_promote(tid):
    with tasks_lock:
        task = tasks.get(tid)
    if not task:
        abort(404)
    if task["status"] != "queued":
        return jsonify({"error": "task is not queued"}), 400
    if not promote(tid):
        return jsonify({"error": "task not in queue"}), 400
    return jsonify({"ok": True})


@app.get("/api/tasks/<tid>")
def api_task(tid):
    with tasks_lock:
        task = tasks.get(tid)
    if not task:
        abort(404)
    return jsonify(task_view(task))


@app.get("/api/tasks/<tid>/download")
def download(tid):
    with tasks_lock:
        task = tasks.get(tid)
    if not task:
        abort(404)
    if task["status"] != "done" or not os.path.exists(task["output_file"]):
        abort(404)
    return send_file(
        task["output_file"],
        as_attachment=True,
        download_name=f"{task['domain']}-subdomains.txt",
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
