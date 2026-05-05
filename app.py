from __future__ import annotations

import base64
import hmac
import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, Response, abort, jsonify, render_template, request, send_file

BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "1800"))
CONFIG_FILE = BASE_DIR / "config.json"
DB_FILE = BASE_DIR / "tasks.db"

BASIC_AUTH_USER = os.environ.get("BASIC_AUTH_USER", "")
BASIC_AUTH_PASS = os.environ.get("BASIC_AUTH_PASS", "")
AUTH_ENABLED = bool(BASIC_AUTH_USER and BASIC_AUTH_PASS)
AUTH_REALM = os.environ.get("BASIC_AUTH_REALM", "subfinder")

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


# ---------------------------------------------------------------- persistence

db_lock = threading.Lock()
_db: sqlite3.Connection | None = None

TASK_COLUMNS = (
    "id", "domain", "status", "created_at", "started_at",
    "finished_at", "count", "error", "output_file",
)


def get_db() -> sqlite3.Connection:
    global _db
    if _db is None:
        conn = sqlite3.connect(str(DB_FILE), check_same_thread=False, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                started_at REAL,
                finished_at REAL,
                count INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                output_file TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at)")
        _db = conn
    return _db


def task_insert(task: dict) -> None:
    with db_lock:
        get_db().execute(
            "INSERT INTO tasks (id, domain, status, created_at, started_at, "
            "finished_at, count, error, output_file) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                task["id"], task["domain"], task["status"], task["created_at"],
                task["started_at"], task["finished_at"], task["count"],
                task["error"], task["output_file"],
            ),
        )


def task_get(tid: str) -> dict | None:
    with db_lock:
        row = get_db().execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()
    return dict(row) if row else None


def task_update(tid: str, **fields) -> int:
    if not fields:
        return 0
    cols = ", ".join(f"{k}=?" for k in fields)
    params = list(fields.values()) + [tid]
    with db_lock:
        return get_db().execute(f"UPDATE tasks SET {cols} WHERE id=?", params).rowcount


def task_update_if_status(tid: str, expected: str, **fields) -> int:
    """Conditional UPDATE; returns rowcount (0 if status moved or row gone)."""
    if not fields:
        return 0
    cols = ", ".join(f"{k}=?" for k in fields)
    params = list(fields.values()) + [tid, expected]
    with db_lock:
        return get_db().execute(
            f"UPDATE tasks SET {cols} WHERE id=? AND status=?", params
        ).rowcount


def task_delete(tid: str) -> int:
    with db_lock:
        return get_db().execute("DELETE FROM tasks WHERE id=?", (tid,)).rowcount


def tasks_all() -> list[dict]:
    with db_lock:
        rows = get_db().execute(
            "SELECT * FROM tasks ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------- in-memory runtime

pending: list[str] = []
pending_cv = threading.Condition()
current_tid: str | None = None

# Per-task transient state that can't live in SQLite. Keyed by task id.
proc_handles: dict[str, subprocess.Popen] = {}
stop_requests: set[str] = set()
runtime_lock = threading.Lock()


def promote(tid: str) -> bool:
    with pending_cv:
        if tid in pending:
            pending.remove(tid)
            pending.insert(0, tid)
            return True
        return False


def task_view(t: dict) -> dict:
    return {k: t[k] for k in (
        "id", "domain", "status", "created_at", "started_at",
        "finished_at", "count", "error",
    )}


def make_task(domain: str) -> dict:
    """Insert a new task and enqueue it atomically so concurrent readers
    never see a task that's persisted but missing from `pending`."""
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
    with db_lock:
        get_db().execute(
            "INSERT INTO tasks (id, domain, status, created_at, started_at, "
            "finished_at, count, error, output_file) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                task["id"], task["domain"], task["status"], task["created_at"],
                task["started_at"], task["finished_at"], task["count"],
                task["error"], task["output_file"],
            ),
        )
        with pending_cv:
            pending.append(tid)
            pending_cv.notify()
    return task


def kill_proc_group(proc: subprocess.Popen) -> None:
    """SIGKILL the process group so children inheriting the pipes also die."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, OSError):
        try:
            proc.kill()
        except Exception:
            pass


def run_scan(tid: str) -> None:
    task = task_get(tid)
    if not task:
        return
    domain = task["domain"]
    output_file = task["output_file"]
    bin_path = get_subfinder_bin()

    # Atomic queued -> running transition. If the row was deleted (or its
    # status changed) between task_get and now, abort before launching
    # subfinder so we don't scan a task that no longer exists and leak its
    # output file onto disk.
    if not task_update_if_status(tid, "queued", status="running", started_at=time.time()):
        return
    try:
        try:
            proc = subprocess.Popen(
                [bin_path, "-d", domain, "-o", output_file, "-silent"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
        except FileNotFoundError:
            task_update(
                tid,
                status="failed",
                error=f"subfinder binary not found: {bin_path} (set it on the page or via SUBFINDER_BIN)",
            )
            return

        # Publish handle, then check whether stop was requested in the tiny
        # window between dequeue and Popen.
        with runtime_lock:
            proc_handles[tid] = proc
            stop_now = tid in stop_requests
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
            task_update(tid, status="failed", error=f"scan timeout after {SCAN_TIMEOUT}s")
            return

        with runtime_lock:
            was_stopped = tid in stop_requests
        if was_stopped:
            task_update(tid, status="stopped", error="cancelled by user")
            return
        if proc.returncode != 0:
            err = (stderr or stdout or "subfinder failed").strip()[:1000]
            task_update(tid, status="failed", error=err)
            return
        if not os.path.exists(output_file):
            open(output_file, "w").close()
        with open(output_file) as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        task_update(tid, count=len(lines), status="done")
    except Exception as e:
        task_update(tid, status="failed", error=str(e))
    finally:
        with runtime_lock:
            proc_handles.pop(tid, None)
            stop_requests.discard(tid)
        task_update(tid, finished_at=time.time())


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
                run_scan(tid)
            finally:
                with pending_cv:
                    current_tid = None
        except Exception as e:
            print(f"worker error processing tid={tid}: {e!r}", file=sys.stderr)


def recover_state() -> None:
    """Bring DB and queue back to a consistent state after a restart:
    any task left as 'running' has a dead subprocess, so mark it failed;
    any 'queued' task is re-enqueued in original creation order."""
    now = time.time()
    with db_lock:
        db = get_db()
        cur = db.execute(
            "UPDATE tasks SET status='failed', error='server restarted while running', "
            "finished_at=? WHERE status='running'",
            (now,),
        )
        recovered_running = cur.rowcount
        rows = db.execute(
            "SELECT id FROM tasks WHERE status='queued' ORDER BY created_at"
        ).fetchall()
    re_enqueued = 0
    if rows:
        with pending_cv:
            for r in rows:
                if r["id"] not in pending:
                    pending.append(r["id"])
                    re_enqueued += 1
            if re_enqueued:
                pending_cv.notify()
    if recovered_running or re_enqueued:
        print(
            f"recovered: {recovered_running} running -> failed, "
            f"{re_enqueued} queued re-enqueued",
            file=sys.stderr,
        )


# ----------------------------------------------------------------- bootstrap

load_config()
get_db()
recover_state()

app = Flask(__name__)


def _check_basic_auth(header: str | None) -> bool:
    if not header or not header.startswith("Basic "):
        return False
    try:
        raw = base64.b64decode(header[6:], validate=True).decode("utf-8", "replace")
    except Exception:
        return False
    user, sep, pwd = raw.partition(":")
    if not sep:
        return False
    return hmac.compare_digest(user, BASIC_AUTH_USER) and hmac.compare_digest(
        pwd, BASIC_AUTH_PASS
    )


@app.before_request
def _basic_auth_gate():
    if not AUTH_ENABLED:
        return None
    if _check_basic_auth(request.headers.get("Authorization")):
        return None
    return Response(
        "Authentication required\n",
        status=401,
        headers={"WWW-Authenticate": f'Basic realm="{AUTH_REALM}"'},
    )


if AUTH_ENABLED:
    print(f"basic auth enabled for user '{BASIC_AUTH_USER}'", file=sys.stderr)
else:
    print(
        "basic auth disabled (set BASIC_AUTH_USER and BASIC_AUTH_PASS to enable)",
        file=sys.stderr,
    )

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
    snapshots = tasks_all()
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

    out = []
    for t in snapshots:
        v = task_view(t)
        if t["status"] == "queued":
            v["position"] = pos.get(t["id"])
        out.append(v)
    return jsonify({"summary": summary, "tasks": out})


@app.post("/api/tasks/<tid>/promote")
def api_promote(tid):
    task = task_get(tid)
    if not task:
        abort(404)
    if task["status"] != "queued" or not promote(tid):
        return jsonify({"error": "task is no longer queued (already running or finished)"}), 400
    return jsonify({"ok": True})


@app.post("/api/tasks/<tid>/stop")
def api_stop(tid):
    task = task_get(tid)
    if not task:
        abort(404)
    if task["status"] not in ("queued", "running"):
        return jsonify({"error": "task is not active"}), 400

    # Try cancelling from the queue first.
    removed = False
    with pending_cv:
        if tid in pending:
            pending.remove(tid)
            removed = True
    if removed:
        task_update(
            tid,
            status="stopped",
            error="cancelled before start",
            finished_at=time.time(),
        )
        return jsonify({"ok": True})

    # Already running (or just dequeued). Re-check status before flagging
    # so the request to stop never lingers on a task the worker just finalized.
    fresh = task_get(tid)
    proc = None
    if fresh and fresh["status"] in ("queued", "running"):
        with runtime_lock:
            stop_requests.add(tid)
            proc = proc_handles.get(tid)
    if proc is not None:
        kill_proc_group(proc)
    return jsonify({"ok": True})


@app.delete("/api/tasks/<tid>")
def api_delete(tid):
    task = task_get(tid)
    if not task:
        abort(404)
    if task["status"] == "running":
        return jsonify({"error": "stop the task before deleting"}), 400

    if task["status"] == "queued":
        with pending_cv:
            try:
                pending.remove(tid)
            except ValueError:
                pass

    output_file = task.get("output_file")
    if output_file:
        try:
            os.unlink(output_file)
        except FileNotFoundError:
            pass
        except OSError:
            pass

    # Re-check: if a race made it 'running' between our checks, refuse.
    fresh = task_get(tid)
    if fresh and fresh["status"] == "running":
        return jsonify({"error": "task started running; stop it first"}), 400
    task_delete(tid)
    return jsonify({"ok": True})


@app.get("/api/tasks/<tid>")
def api_task(tid):
    task = task_get(tid)
    if not task:
        abort(404)
    return jsonify(task_view(task))


@app.get("/api/tasks/<tid>/download")
def download(tid):
    task = task_get(tid)
    if not task or task["status"] != "done":
        abort(404)
    output_file = task["output_file"]
    download_name = f"{task['domain']}-subdomains.txt"
    try:
        return send_file(output_file, as_attachment=True, download_name=download_name)
    except FileNotFoundError:
        abort(404)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
