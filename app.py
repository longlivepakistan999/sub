from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
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
CONFIG_FILE = BASE_DIR / "config.json"

config_lock = threading.Lock()
config: dict = {"subfinder_bin": os.environ.get("SUBFINDER_BIN", "subfinder")}


def load_config() -> None:
    if not CONFIG_FILE.exists():
        return
    try:
        data = json.loads(CONFIG_FILE.read_text())
    except Exception as e:
        print(
            f"warning: could not parse {CONFIG_FILE} ({e}); "
            "falling back to defaults — re-save from the UI to overwrite it",
            file=sys.stderr,
        )
        return
    bin_path = data.get("subfinder_bin")
    if isinstance(bin_path, str) and bin_path.strip():
        with config_lock:
            config["subfinder_bin"] = bin_path.strip()


def _persist_config_locked(snapshot: dict) -> None:
    """Write config atomically. Caller must serialize (e.g. hold config_lock)."""
    tmp = CONFIG_FILE.with_suffix(CONFIG_FILE.suffix + ".tmp")
    tmp.write_text(json.dumps(snapshot, indent=2))
    os.replace(tmp, CONFIG_FILE)


def save_config() -> None:
    with config_lock:
        _persist_config_locked(dict(config))


def get_subfinder_bin() -> str:
    with config_lock:
        return config["subfinder_bin"]


def probe_subfinder(path: str) -> dict:
    result = {"bin": path, "ok": False, "version": None, "error": None}
    try:
        proc = subprocess.run(
            [path, "-version"], capture_output=True, text=True, timeout=5,
        )
        out = (proc.stderr or proc.stdout or "").strip()
        if proc.returncode != 0:
            result["error"] = (out or f"exit {proc.returncode}")[:200]
        elif "subfinder" not in out.lower():
            result["error"] = f"binary did not identify as subfinder: {out[:200] or '(no output)'}"
        else:
            result["ok"] = True
            result["version"] = out[:200]
    except FileNotFoundError:
        result["error"] = "binary not found"
    except subprocess.TimeoutExpired:
        result["error"] = "probe timeout"
    except PermissionError:
        result["error"] = "permission denied"
    except Exception as e:
        result["error"] = str(e)[:200]
    return result


load_config()

app = Flask(__name__)

tasks: dict[str, dict] = {}
tasks_lock = threading.Lock()

pending: list[str] = []
pending_cv = threading.Condition()
current_tid: str | None = None


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
    """Register a new task and enqueue it atomically so concurrent readers
    never see a task that exists in `tasks` but is missing from `pending`."""
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
        with pending_cv:
            pending.append(tid)
            pending_cv.notify()
    return task


def update_task(task: dict, **fields) -> None:
    with tasks_lock:
        task.update(fields)


def kill_proc_group(proc: subprocess.Popen) -> None:
    """SIGKILL the process group so children inheriting the pipes also die."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, OSError):
        try:
            proc.kill()
        except Exception:
            pass


def run_scan(task: dict) -> None:
    update_task(task, status="running", started_at=time.time())
    output_file = task["output_file"]
    bin_path = get_subfinder_bin()
    try:
        try:
            proc = subprocess.Popen(
                [bin_path, "-d", task["domain"], "-o", output_file, "-silent"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
        except FileNotFoundError:
            update_task(
                task,
                status="failed",
                error=f"subfinder binary not found: {bin_path} (set it on the page or via SUBFINDER_BIN)",
            )
            return

        # Publish proc handle, then check whether stop was requested in
        # the tiny window between dequeue and Popen.
        with tasks_lock:
            task["_proc"] = proc
            stop_now = task.get("_stop_requested", False)
        if stop_now:
            kill_proc_group(proc)
        try:
            stdout, stderr = proc.communicate(timeout=SCAN_TIMEOUT)
        except subprocess.TimeoutExpired:
            kill_proc_group(proc)
            try:
                proc.communicate(timeout=5)
            except Exception:
                pass
            update_task(task, status="failed", error=f"scan timeout after {SCAN_TIMEOUT}s")
            return

        with tasks_lock:
            was_stopped = task.get("_stop_requested", False)
        if was_stopped:
            update_task(task, status="stopped", error="cancelled by user")
            return
        if proc.returncode != 0:
            err = (stderr or stdout or "subfinder failed").strip()[:1000]
            update_task(task, status="failed", error=err)
            return
        if not os.path.exists(output_file):
            open(output_file, "w").close()
        with open(output_file) as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        update_task(task, count=len(lines), status="done")
    except Exception as e:
        update_task(task, status="failed", error=str(e))
    finally:
        with tasks_lock:
            task.pop("_proc", None)
            task.pop("_stop_requested", None)
        update_task(task, finished_at=time.time())


def worker() -> None:
    global current_tid
    while True:
        tid = None
        try:
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
        except Exception as e:
            # Never let the worker thread die — without it queued tasks
            # would silently stop processing while the server stayed up.
            print(f"worker error processing tid={tid}: {e!r}", file=sys.stderr)


threading.Thread(target=worker, daemon=True).start()


@app.route("/")
def index():
    return render_template("index.html")


@app.get("/api/config")
def api_config_get():
    probe_path = (request.args.get("bin") or "").strip()
    bin_path = probe_path or get_subfinder_bin()
    result = probe_subfinder(bin_path)
    result["saved_bin"] = get_subfinder_bin()
    return jsonify(result)


@app.post("/api/config")
def api_config_set():
    data = request.get_json(silent=True) or request.form
    bin_path = (data.get("subfinder_bin") or "").strip()
    if not bin_path:
        return jsonify({"error": "subfinder_bin is required"}), 400
    probe = probe_subfinder(bin_path)
    if not probe["ok"]:
        return jsonify(probe), 400
    with config_lock:
        config["subfinder_bin"] = bin_path
        try:
            _persist_config_locked(dict(config))
        except Exception as e:
            return jsonify({"error": f"saved in memory but failed to persist: {e}"}), 500
    return jsonify(probe)


def parse_domains(raw) -> list[str]:
    if isinstance(raw, list):
        items = raw
    else:
        items = re.split(r"[\s,;]+", str(raw or ""))
    seen, out = set(), []
    for item in items:
        d = item.strip().lower()
        if d.startswith("*."):
            d = d[2:]
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
            accepted.append(task_view(task))
        else:
            rejected.append(d)
    if not accepted:
        return jsonify({"error": "invalid domain", "rejected": rejected}), 400
    return jsonify({"accepted": accepted, "rejected": rejected}), 201


@app.get("/api/tasks")
def api_tasks():
    with tasks_lock:
        snapshots = [task_view(t) for t in tasks.values()]
    snapshots.sort(key=lambda t: t["created_at"], reverse=True)
    with pending_cv:
        order = list(pending)
        running_id = current_tid
    pos = {tid: i + 1 for i, tid in enumerate(order)}

    # current_tid is set the moment the worker pops a task from pending,
    # which can be a tick before run_scan flips its status to "running".
    # Treat the popped task as running so the summary stays consistent.
    if running_id:
        for t in snapshots:
            if t["id"] == running_id and t["status"] == "queued":
                t["status"] = "running"
                break

    counts = {"queued": 0, "running": 0, "done": 0, "failed": 0, "stopped": 0}
    current_domain = None
    for t in snapshots:
        counts[t["status"]] = counts.get(t["status"], 0) + 1
        if t["id"] == running_id:
            current_domain = t["domain"]

    summary = {
        "total": len(snapshots),
        "queued": counts["queued"],
        "running": counts["running"],
        "done": counts["done"],
        "failed": counts["failed"],
        "stopped": counts["stopped"],
        "finished": counts["done"] + counts["failed"] + counts["stopped"],
        "current_domain": current_domain,
    }

    for t in snapshots:
        if t["status"] == "queued":
            t["position"] = pos.get(t["id"])
    return jsonify({"summary": summary, "tasks": snapshots})


@app.post("/api/tasks/<tid>/promote")
def api_promote(tid):
    with tasks_lock:
        task = tasks.get(tid)
        status = task["status"] if task else None
    if not task:
        abort(404)
    if status != "queued" or not promote(tid):
        return jsonify({"error": "task is no longer queued (already running or finished)"}), 400
    return jsonify({"ok": True})


@app.post("/api/tasks/<tid>/stop")
def api_stop(tid):
    with tasks_lock:
        task = tasks.get(tid)
        if not task:
            abort(404)
        status = task["status"]
    if status not in ("queued", "running"):
        return jsonify({"error": "task is not active"}), 400

    # Try cancelling from the queue first.
    removed = False
    with pending_cv:
        if tid in pending:
            pending.remove(tid)
            removed = True
    if removed:
        update_task(
            task,
            status="stopped",
            error="cancelled before start",
            finished_at=time.time(),
        )
        return jsonify({"ok": True})

    # Already running (or just dequeued). Re-check status under the lock
    # so we don't strand a stale flag on a task the worker just finalized.
    with tasks_lock:
        if task["status"] in ("queued", "running"):
            task["_stop_requested"] = True
            proc = task.get("_proc")
        else:
            proc = None
    if proc is not None:
        kill_proc_group(proc)
    return jsonify({"ok": True})


@app.delete("/api/tasks/<tid>")
def api_delete(tid):
    with tasks_lock:
        task = tasks.get(tid)
        if not task:
            abort(404)
        status = task["status"]
        output_file = task.get("output_file")
    if status == "running":
        return jsonify({"error": "stop the task before deleting"}), 400

    if status == "queued":
        with pending_cv:
            try:
                pending.remove(tid)
            except ValueError:
                pass

    if output_file:
        try:
            os.unlink(output_file)
        except FileNotFoundError:
            pass
        except OSError:
            pass

    with tasks_lock:
        # Re-check: if a race made it 'running' between our checks, refuse.
        cur = tasks.get(tid)
        if cur and cur["status"] == "running":
            return jsonify({"error": "task started running; stop it first"}), 400
        tasks.pop(tid, None)
    return jsonify({"ok": True})


@app.get("/api/tasks/<tid>")
def api_task(tid):
    with tasks_lock:
        task = tasks.get(tid)
        view = task_view(task) if task else None
    if view is None:
        abort(404)
    return jsonify(view)


@app.get("/api/tasks/<tid>/download")
def download(tid):
    with tasks_lock:
        task = tasks.get(tid)
        if task and task["status"] == "done":
            output_file = task["output_file"]
            download_name = f"{task['domain']}-subdomains.txt"
        else:
            output_file = None
    if not output_file:
        abort(404)
    try:
        return send_file(output_file, as_attachment=True, download_name=download_name)
    except FileNotFoundError:
        abort(404)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
