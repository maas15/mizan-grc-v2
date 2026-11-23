#!/usr/bin/env python3
"""One supervised native Gunicorn run; no app imports or renderer replacements.

Supply an exact reviewed checkout and a NONEXISTENT run root. The font build
step must have completed beforehand. Only run-root/evidence is publishable;
run-root/private contains the disposable database, credentials and temp files.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
from http.client import HTTPConnection
from http.cookies import SimpleCookie
import importlib.metadata
import io
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import time
import traceback
from urllib.parse import urlencode
import uuid
import xml.etree.ElementTree as ET
from zipfile import ZipFile

SOURCE_HEAD = "3b713191631cb67580424bdf2d9461827f05ec02"
SOURCE_TREE = "c9a55999fae334af6ebe953b30b63b5741d87768"
SOURCE_INDEX_SHA256 = "578c0c4abf867ac2110b18951c72883e65c4afd9ddaf56405ae3d7e6d611e581"
FONT = "static/fonts/Amiri-Regular.ttf"
CORE = dict(workers=2, threads=4, timeout=600, keepalive=5,
            max_requests=1000, max_requests_jitter=100, preload_app=False)
TOTAL_SECONDS, RENDER_SECONDS, SHUTDOWN_SECONDS, POSTFLIGHT_SECONDS = 900, 300, 30, 30


class VerificationFailure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise VerificationFailure(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    temporary = path.with_name(path.name + ".writing")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def proc(pid):
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    tail = raw.rsplit(")", 1)[1].split()
    return dict(pid=pid, state=tail[0], ppid=int(tail[1]), pgid=int(tail[2]),
                session=int(tail[3]), start_ticks=int(tail[19]))


def group_members(pgid):
    result = []
    for item in Path("/proc").iterdir():
        if item.name.isdecimal():
            try:
                value = proc(int(item.name))
            except (OSError, ValueError, IndexError):
                continue
            if value and value["pgid"] == pgid and value["session"] == pgid:
                result.append(value)
    return sorted(result, key=lambda x: x["pid"])


class Events:
    def __init__(self, directory):
        self.directory, self.files, self.events = directory, {}, []

    def read(self):
        for path in sorted(self.directory.glob("observer-*.jsonl")):
            state = self.files.setdefault(str(path), dict(offset=0, pending=b""))
            with path.open("rb") as stream:
                stream.seek(state["offset"])
                data = state["pending"] + stream.read()
                state["offset"] = stream.tell()
            lines = data.split(b"\n")
            state["pending"] = lines.pop()
            for line in lines:
                if line:
                    self.events.append(json.loads(line))
        return self.events


class Actor:
    def __init__(self, values):
        self.id, self.username, self.password = values["id"], values["username"], values["password"]
        self.cookies, self.csrf = {}, None
        self.secret_values = {self.password}

    def header(self):
        cookie = SimpleCookie()
        for key, value in self.cookies.items():
            cookie[key] = value
        return "; ".join(f"{key}={morsel.coded_value}" for key, morsel in cookie.items())

    def update(self, headers):
        for key, value in headers:
            if key.lower() == "set-cookie":
                cookie = SimpleCookie()
                cookie.load(value)
                for name, morsel in cookie.items():
                    if morsel["max-age"] == "0" or not morsel.value:
                        self.cookies.pop(name, None)
                    else:
                        self.cookies[name] = morsel.value
                        self.secret_values.add(morsel.value)
            elif key.lower() == "x-csrftoken":
                self.csrf = value
                self.secret_values.add(value)


class Channel:
    def __init__(self, run, deadline=None):
        self.run, self.pid = run, None
        left = min(run.deadline, deadline if deadline is not None else run.deadline) - time.monotonic()
        require(left > 0, "Connection setup deadline expired")
        self.http = HTTPConnection("127.0.0.1", run.port, timeout=min(3, left))
        self.http.connect()
        self.http.auto_open = 0
        self.sock = self.http.sock
        self.connection = dict(local=list(self.sock.getsockname()), peer=list(self.sock.getpeername()))
        run.channels.append(self)

    def close(self):
        self.http.close()

    def request(self, method, path, actor, body=None, content_type=None,
                label="probe", timeout=10, deadline=None):
        run = self.run
        run.check_pool()
        require(self.http.sock is self.sock and self.sock.fileno() >= 0,
                "Persistent socket is closed; automatic reconnect is prohibited")
        deadline = min(run.deadline, deadline if deadline is not None else run.deadline)
        require(time.monotonic() < deadline, "Request/case deadline expired before send")
        self.sock.settimeout(min(timeout, deadline - time.monotonic()))
        rid = uuid.uuid4().hex
        headers = {"X-Mizan-Probe-ID": rid, "Connection": "keep-alive"}
        if actor is not None and actor.cookies:
            headers["Cookie"] = actor.header()
        if actor is not None and actor.csrf:
            headers["X-CSRFToken"] = actor.csrf
        if content_type:
            headers["Content-Type"] = content_type
        entry = dict(request_id=rid, label=label, method=method, path=path,
                     actor_id=actor.id if actor else None, connection=self.connection,
                     started_utc=utc(), expected_worker=self.pid)
        try:
            self.http.request(method, path, body=body, headers=headers)
            response = self.http.getresponse()
            data = response.read()
            pairs = response.getheaders()
            result = dict(status=response.status, headers=dict(pairs), body=data,
                          will_close=response.will_close)
            response.close()
            entry.update(status=result["status"], response_bytes=len(data), response_sha256=sha(data))
            if path.startswith("/api/") and label != "affinity_probe" and result["status"] >= 400:
                bodies = run.evidence / "http-error-bodies"
                bodies.mkdir(exist_ok=True)
                body_path = bodies / (rid + ".bin")
                body_path.write_bytes(data)
                entry["raw_error_body"] = str(body_path.relative_to(run.evidence))
            if actor is not None:
                actor.update(pairs)
            require(time.monotonic() < deadline, "HTTP response arrived after request/case deadline")
            end = run.request_event(rid, deadline)
            observed = int(end["status"].split()[0])
            require(observed == result["status"], "HTTP status differs from native worker observation")
            require(end["method"] == method and end["path"] == path, "Request observation mismatch")
            if self.pid is None:
                self.pid = end["pid"]
            require(end["pid"] == self.pid and end["ppid"] == run.master.pid,
                    "Request changed worker or master")
            require(self.pid in run.workers, "Request was handled by an unverified worker")
            entry.update(worker_pid=end["pid"], master_pid=end["ppid"], status=result["status"],
                         response_bytes=len(data), response_sha256=sha(data),
                         connection_closed=result["will_close"],
                         response_headers={key: value for key, value in pairs if key.lower() in
                                           {"content-type", "content-length", "content-disposition", "location"}})
            run.check_pool()
            return result
        except BaseException as exc:
            entry["error"] = type(exc).__name__ + ": " + str(exc)
            raise
        finally:
            entry["ended_utc"] = utc()
            with (run.evidence / "http-events.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, ensure_ascii=False) + "\n")


class Run:
    def __init__(self, source, root):
        self.source, self.root = source.resolve(), root.resolve()
        require(sys.platform.startswith("linux"), "This verification requires native Linux")
        require(not self.root.exists(), "Run root already exists; do not reuse or rerun it")
        require(self.source not in self.root.parents and self.root not in self.source.parents
                and self.root != self.source, "Run root and source must be separate")
        self.root.mkdir(parents=True)
        self.evidence, self.private = self.root / "evidence", self.root / "private"
        self.evidence.mkdir()
        self.private.mkdir(mode=0o700)
        self.tmp = self.private / "tmp"
        self.tmp.mkdir(mode=0o700)
        self.db = self.private / "app.db"
        self.deadline = time.monotonic() + TOTAL_SECONDS
        self.master, self.workers, self.channels = None, {}, []
        self.events = Events(self.evidence)
        self.receipt = dict(kind="Native Linux Gunicorn two-worker verification", started_utc=utc(),
                            limits=dict(total_seconds=TOTAL_SECONDS, render_seconds=RENDER_SECONDS,
                                        shutdown_seconds=SHUTDOWN_SECONDS,
                                        readonly_postflight_seconds=POSTFLIGHT_SECONDS,
                                        configured_budget_seconds=960),
                            source_head=SOURCE_HEAD, cases={}, success=False, phase="preflight")
        self.save()

    def save(self):
        text = json.dumps(self.receipt, ensure_ascii=False)
        for value in self.known_secrets():
            text = text.replace(value, "[REDACTED]")
        write_json(self.evidence / "run-status.json", json.loads(text))

    def known_secrets(self):
        values = set()
        for name in ("SECRET_KEY", "ADMIN_PASSWORD"):
            value = getattr(self, "env", {}).get(name)
            if value:
                values.add(value)
        for name in ("owner", "other"):
            actor = getattr(self, name, None)
            if actor:
                values.update(actor.secret_values)
        return sorted((value for value in values if value), key=len, reverse=True)

    def phase(self, value):
        self.receipt["phase"] = value
        self.save()
        print(json.dumps(dict(phase=value, utc=utc())), flush=True)

    def remaining(self):
        value = self.deadline - time.monotonic()
        require(value > 0, "Overall 900-second execution budget expired")
        return value

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.source), *args],
                                       timeout=min(30, self.remaining()))

    def source_snapshot(self):
        head = self.git("rev-parse", "HEAD").decode().strip()
        tree = self.git("rev-parse", "HEAD^{tree}").decode().strip()
        index = self.git("ls-files", "--stage", "-z")
        require(head == SOURCE_HEAD and tree == SOURCE_TREE, "Reviewed source commit/tree mismatch")
        require(sha(index) == SOURCE_INDEX_SHA256, "Reviewed raw index mismatch")
        tracked, verified = set(), 0
        for item in index.split(b"\0"):
            if not item:
                continue
            header, name = item.split(b"\t", 1)
            mode, oid, stage = header.split()
            relative = name.decode("utf-8")
            tracked.add(relative)
            path = self.source / relative
            require(stage == b"0" and mode in (b"100644", b"100755") and not path.is_symlink(),
                    "Unsupported index stage/mode/path")
            content = path.read_bytes()
            blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
            require(blob == oid.decode(), "Tracked file bytes changed: " + relative)
            verified += 1
        require(verified == 532, "Unexpected source count")
        subprocess.run(["git", "-C", str(self.source), "diff", "--quiet", "HEAD", "--"],
                       check=True, timeout=min(30, self.remaining()))
        present = {p.relative_to(self.source).as_posix() for p in self.source.rglob("*")
                   if (p.is_file() or p.is_symlink()) and p.relative_to(self.source).parts[0] != ".git"}
        require(present - tracked == {FONT}, "Only the explicitly built Amiri font may be untracked")
        font = self.source / FONT
        require(font.is_file() and not font.is_symlink(), "Required font build output missing/unsafe")
        font_bytes = font.read_bytes()
        require(font_bytes, "Font build output is empty")
        require(not (self.source / ".secret_key").exists(), "Adjacent .secret_key appeared")
        result = dict(head=head, tree=tree, index_entries=verified, index_stage_z_sha256=sha(index),
                      tracked_bytes_verified=verified, untracked_build_assets=[FONT],
                      font=dict(path=FONT, bytes=len(font_bytes), sha256=sha(font_bytes),
                                git_blob_oid=hashlib.sha1(b"blob " + str(len(font_bytes)).encode()
                                                         + b"\0" + font_bytes).hexdigest()),
                      adjacent_secret_key=False,
                      porcelain_status=self.git("status", "--porcelain=v1", "--untracked-files=all").decode())
        return result, index

    def preflight(self):
        snapshot, index = self.source_snapshot()
        self.receipt["source_before"] = snapshot
        (self.evidence / "source-index.stage-z").write_bytes(index)
        write_json(self.evidence / "source-before.json", snapshot)
        expected_python = (self.source / ".python-version").read_text().strip()
        require(platform.python_version() == expected_python == "3.12.10", "Python target mismatch")
        versions = {dist.metadata["Name"]: dist.version for dist in importlib.metadata.distributions()
                    if dist.metadata.get("Name")}
        require("gunicorn" in {name.lower() for name in versions}, "Gunicorn is not installed")
        write_json(self.evidence / "runtime-versions.json",
                   dict(python=sys.version, executable=sys.executable, platform=platform.platform(),
                        os_release=Path("/etc/os-release").read_text(), distributions=versions))
        kit = Path(__file__).resolve().parent
        self.config, self.seeder = kit / "gunicorn_observer_config.py", kit / "seed_native_fixture.py"
        self.receipt["helper_sha256"] = {p.name: sha(p.read_bytes()) for p in
                                         [Path(__file__).resolve(), self.config, self.seeder]}
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        self.receipt["port"] = self.port
        env = os.environ.copy()
        for name in list(env):
            if (name.startswith(("PYTEST", "OPENAI_", "ANTHROPIC_", "GOOGLE_", "GEMINI_", "GROQ_"))
                    or name.startswith("REL") or name.startswith("MIZAN_")
                    or name in {"DATABASE_URL", "DATABASE_PATH", "SECRET_KEY", "ADMIN_PASSWORD",
                                "TESTING", "FLASK_ENV", "FLASK_DEBUG", "GUNICORN_CMD_ARGS",
                                "PYTHONPATH", "PYTHONHOME", "PYTHONOPTIMIZE", "PYTHONSTARTUP"}):
                env.pop(name, None)
        env.update(DATABASE_PATH=str(self.db), MIZAN_DOCX_DATABASE_PATH=str(self.db),
                   TMP=str(self.tmp), TEMP=str(self.tmp), TMPDIR=str(self.tmp),
                   SECRET_KEY=secrets.token_urlsafe(48), ADMIN_PASSWORD=secrets.token_urlsafe(32),
                   PYTHONDONTWRITEBYTECODE="1", PYTHON_DOTENV_DISABLED="1", PYTHONUTF8="1",
                   PORT=str(self.port), MIZAN_NATIVE_PORT=str(self.port),
                   MIZAN_NATIVE_SOURCE_ROOT=str(self.source),
                   MIZAN_NATIVE_OBSERVER_DIR=str(self.evidence))
        self.env = env
        self.receipt["environment_policy"] = dict(
            shared_database=True, shared_ephemeral_secret=True, api_keys_supplied=False,
            testing_flags_supplied=False, export_evidence_bypass_supplied=False,
            bind_override="127.0.0.1", private_state_directory=str(self.private))
        self.save()

    def start(self):
        self.phase("server_start")
        command = [sys.executable, "-B", "-m", "gunicorn", "-c", str(self.config), "app:app"]
        self.receipt["command"] = command
        with (self.evidence / "gunicorn-stdout.txt").open("xb") as out, \
                (self.evidence / "gunicorn-stderr.txt").open("xb") as err:
            self.master = subprocess.Popen(command, cwd=self.source, env=self.env,
                                           stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                           start_new_session=True)
        self.receipt["master_pid"] = self.master.pid
        self.receipt["master_process"] = proc(self.master.pid)
        self.save()
        deadline = min(self.deadline, time.monotonic() + 180)
        while time.monotonic() < deadline:
            require(self.master.poll() is None, "Gunicorn master exited before workers were ready")
            initialized = [e for e in self.events.read() if e["event"] == "worker_initialized"]
            if len(initialized) >= 2:
                require(len(initialized) == 2, "Unexpected worker replacement during startup")
                for event in initialized:
                    require(event["ppid"] == self.master.pid, "Worker is not a child of this master")
                    require(event["worker_class"] == "gunicorn.workers.gthread.ThreadWorker",
                            "Effective worker is not production gthread")
                    require(all(event["effective"].get(k) == v for k, v in CORE.items()),
                            "Effective production settings changed")
                    require(Path(event["app_module_path"]).resolve() == self.source / "app.py",
                            "Gunicorn loaded another app module")
                    require(Path(event["database_path"]).resolve() == self.db, "Worker DB mismatch")
                    value = proc(event["pid"])
                    require(value is not None, "Initialized worker already ended")
                    self.workers[event["pid"]] = value
                require(len(self.workers) == 2, "Two distinct worker processes were not established")
                self.check_pool()
                self.receipt["workers"] = initialized
                self.receipt["worker_processes"] = self.workers
                self.save()
                return
            time.sleep(0.1)
        raise VerificationFailure("Two workers did not initialize within 180 seconds")

    def check_pool(self):
        self.remaining()
        require(self.master is not None and self.master.poll() is None, "Gunicorn master ended")
        master = proc(self.master.pid)
        require(master and master["pgid"] == self.master.pid and master["session"] == self.master.pid,
                "Owned process-group identity changed")
        if not self.workers:
            return
        children = Path(f"/proc/{self.master.pid}/task/{self.master.pid}/children").read_text().split()
        require(set(map(int, children)) == set(self.workers), "Gunicorn worker set changed")
        for pid, before in self.workers.items():
            now = proc(pid)
            require(now and now["state"] != "Z" and now["ppid"] == self.master.pid
                    and now["start_ticks"] == before["start_ticks"], "Worker identity or lifetime changed")
        initialized = [e for e in self.events.read() if e["event"] == "worker_initialized"]
        require(len(initialized) == 2, "Additional worker initialization occurred")

    def request_event(self, rid, request_deadline=None):
        deadline = min(self.deadline, time.monotonic() + 3,
                       request_deadline if request_deadline is not None else self.deadline)
        while time.monotonic() < deadline:
            events = self.events.read()
            ends = [e for e in events if e["event"] == "request_end" and e.get("request_id") == rid]
            if ends:
                starts = [e for e in events if e["event"] == "request_start" and e.get("request_id") == rid]
                require(len(ends) == len(starts) == 1 and starts[0]["pid"] == ends[0]["pid"],
                        "Request PID observation was missing, duplicated or inconsistent")
                return ends[0]
            self.check_pool()
            time.sleep(0.02)
        raise VerificationFailure("Native request PID observation did not arrive within the request/case deadline")

    def seed_and_login(self):
        self.phase("seed_and_real_login")
        public, private = self.evidence / "bootstrap.json", self.private / "bootstrap.json"
        command = [sys.executable, "-B", str(self.seeder), "--source", str(self.source),
                   "--database", str(self.db), "--output", str(public), "--private-output", str(private)]
        with (self.evidence / "seed-stdout.txt").open("xb") as out, \
                (self.evidence / "seed-stderr.txt").open("xb") as err:
            result = subprocess.run(command, env=self.env, cwd=self.source, stdout=out, stderr=err,
                                    timeout=min(30, self.remaining()))
        require(result.returncode == 0, "Fixture seeding failed; see its retained logs")
        self.receipt["seed_exit_code"] = result.returncode
        bootstrap = json.loads(private.read_text())
        self.owner, self.other = Actor(bootstrap["users"]["owner"]), Actor(bootstrap["users"]["other"])
        require(self.owner.id == 7 and self.other.id == 8, "Fixture owner IDs changed")
        self.payloads, self.markers = bootstrap["payloads"], bootstrap["expected_markers"]
        for actor in [self.owner, self.other]:
            channel = Channel(self)
            try:
                body = urlencode(dict(username=actor.username, password=actor.password)).encode()
                response = channel.request("POST", "/login", actor, body,
                                           "application/x-www-form-urlencoded", "real_login", 30)
                require(response["status"] == 302 and actor.cookies and actor.csrf,
                        "Real login did not establish a session and CSRF token")
            finally:
                channel.close()
        self.receipt["real_login"] = dict(owner_id=7, other_id=8, redirects_followed=False,
                                          cookies_and_csrf_observed=True)
        # Confirm both workers can handle authenticated persistent connections
        # before any export is created. These harmless probes do not create tasks.
        for pid in sorted(self.workers):
            channel = self.acquire(pid)
            channel.close()
        self.receipt["initial_affinity_setup_passed"] = True
        self.save()

    def acquire(self, pid, case_deadline=None):
        deadline = min(self.deadline, time.monotonic() + 30,
                       case_deadline if case_deadline is not None else self.deadline)
        failures = []
        for attempt in range(32):
            if time.monotonic() >= deadline:
                break
            channel = None
            try:
                channel = Channel(self, deadline)
                path = "/api/export-status/" + str(uuid.uuid4())
                result = channel.request("GET", path, self.owner, label="affinity_probe",
                                         timeout=min(3, max(0.01, deadline - time.monotonic())),
                                         deadline=deadline)
                require(result["status"] == 404, "Authenticated harmless probe did not return404")
                require(time.monotonic() < deadline, "Worker affinity setup deadline exceeded")
                if channel.pid == pid and not result["will_close"]:
                    return channel
            except (OSError, TimeoutError) as exc:
                failures.append(type(exc).__name__ + ": " + str(exc))
            finally:
                if channel is not None and (channel.pid != pid or channel.http.sock is None):
                    channel.close()
            if channel is not None:
                channel.close()
        raise VerificationFailure(f"Could not acquire persistent worker{pid} within bounded setup: {failures}")

    def task_row(self, task):
        with closing(sqlite3.connect(self.db.as_uri() + "?mode=ro", uri=True, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT task_id,user_id,record_id,fmt,filename,status,tmp,error FROM export_tasks WHERE task_id=?",
                (task,)).fetchone()
        require(row is not None, "Task is missing from shared SQLite")
        return dict(row)

    def file_bytes(self, row, fmt, task):
        path = Path(row["tmp"])
        require(path.is_absolute() and self.tmp in path.resolve().parents
                and not path.is_symlink() and stat.S_ISREG(path.lstat().st_mode),
                "Server task path is outside the disposable temporary directory")
        require(path.name.startswith("mizan_export_" + task + "_") and path.suffix == "." + fmt,
                "Unexpected server-generated task filename")
        return path.read_bytes()

    def validate_document(self, fmt, body, folder):
        if fmt == "docx":
            with ZipFile(io.BytesIO(body)) as archive:
                require("[Content_Types].xml" in archive.namelist(), "DOCX content types absent")
                tree = ET.fromstring(archive.read("word/document.xml"))
            text = "\n".join(x.text or "" for x in tree.iter()
                             if x.tag == "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t")
            details = dict(format="docx", document_xml_parsed=True, text_characters=len(text))
        else:
            import pymupdf
            with pymupdf.open(stream=body, filetype="pdf") as document:
                require(document.page_count > 0 and not document.needs_pass, "PDF is empty/encrypted")
                text = "\n".join(page.get_text("text") for page in document)
                details = dict(format="pdf", parser="pymupdf", pages=document.page_count,
                               text_characters=len(text))
        require(text.strip(), "Delivered document contains no extractable text")
        marker_list = list(self.markers) if isinstance(self.markers, (list, tuple, dict)) else []
        details["fixture_markers_observed"] = {str(marker): str(marker) in text for marker in marker_list}
        details["marker_scope"] = "Diagnostic extraction; no new content/layout oracle or F003 closure"
        (folder / "extracted-text.txt").write_text(text, encoding="utf-8")
        write_json(folder / "document-inspection.json", details)
        return details

    def case(self, fmt, producer, consumer):
        self.phase("real_" + fmt)
        folder = self.evidence / fmt
        folder.mkdir()
        result = dict(format=fmt, producer_pid=producer, consumer_pid=consumer, success=False,
                      create_attempts=0, consuming_download_attempts=0, observed_states=[])
        self.receipt["cases"][fmt] = result
        creator, reader = None, None
        try:
            creator = self.acquire(producer)
            payload = dict(self.payloads[fmt])
            require(not any(key.startswith("_") for key in payload), "Private request flags prohibited")
            request_body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
            result["request_body_sha256"] = sha(request_body)
            result["create_attempts"] += 1
            case_deadline = min(self.deadline, time.monotonic() + RENDER_SECONDS)
            self.save()
            response = creator.request("POST", "/api/generate-" + fmt + "-async", self.owner,
                                       request_body, "application/json", fmt + "_create_once", 60,
                                       deadline=case_deadline)
            require(time.monotonic() < case_deadline, "Creation response exceeded render deadline")
            result["create_http_status"] = response["status"]
            result["create_response"] = json.loads(response["body"])
            require(response["status"] == 200, "Real " + fmt + " creation was refused")
            task = result["create_response"].get("task_id")
            require(isinstance(task, str) and str(uuid.UUID(task)) == task, "Invalid task ID")
            result["task_id"] = task
            result["initial_task_row"] = self.task_row(task)
            creator.close()
            creator = None
            # Explicit new connection, not reuse of an idle creator socket.
            reader = self.acquire(consumer, case_deadline)
            status_path, download_path = "/api/export-status/" + task, "/api/export-download/" + task
            while time.monotonic() < case_deadline:
                response = reader.request("GET", status_path, self.owner, label=fmt + "_owner_status",
                                          timeout=min(10, max(0.01, case_deadline - time.monotonic())),
                                          deadline=case_deadline)
                require(time.monotonic() < case_deadline, "Owner status arrived after render deadline")
                state = json.loads(response["body"])
                result["last_owner_status"] = dict(http=response["status"], body=state)
                if not result["observed_states"] or result["observed_states"][-1] != state.get("status"):
                    result["observed_states"].append(state.get("status"))
                require(response["status"] == 200, "Real " + fmt + " generation failed: " + repr(state))
                if state.get("status") == "done":
                    break
                require(state.get("status") == "pending", "Unexpected owner task status")
                self.save()
                time.sleep(min(1, max(0, case_deadline - time.monotonic())))
            else:
                raise VerificationFailure("Real " + fmt + " generation exceeded300seconds")
            row = self.task_row(task)
            require(row["user_id"] == 7 and row["record_id"] == 702 and row["fmt"] == fmt
                    and row["status"] == "done", "Completed shared task identity mismatch")
            server_bytes = self.file_bytes(row, fmt, task)
            (folder / ("server-produced." + fmt)).write_bytes(server_bytes)
            result["completed_task_row"] = row
            result["server_file"] = dict(bytes=len(server_bytes), sha256=sha(server_bytes))
            denials = []
            for path in (status_path, download_path):
                denied = reader.request("GET", path, self.other, label=fmt + "_nonowner_denial")
                denial = dict(path=path, http=denied["status"], body=json.loads(denied["body"]))
                denials.append(denial)
                require(denied["status"] == 403 and denial["body"].get("reason") == "export_task_not_owned",
                        "Nonowner denial was not the owned-task guard")
            result["nonowner_denials"] = denials
            require(self.task_row(task) == row and self.file_bytes(row, fmt, task) == server_bytes,
                    "Nonowner access changed or consumed the task/file")
            result["nonowner_did_not_consume"] = True
            ready = reader.request("GET", status_path, self.owner, label=fmt + "_owner_ready")
            require(ready["status"] == 200 and json.loads(ready["body"]).get("status") == "done",
                    "Owner readiness changed before the single consuming download")
            result["consuming_download_attempts"] += 1
            self.save()
            delivered = reader.request("GET", download_path, self.owner,
                                       label=fmt + "_owner_download_once", timeout=45)
            result["download_http_status"] = delivered["status"]
            require(delivered["status"] == 200, "Owner download failed")
            expected_mime = ("application/pdf" if fmt == "pdf" else
                             "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
            lower_headers = {key.lower(): value for key, value in delivered["headers"].items()}
            require(lower_headers.get("content-type", "").split(";", 1)[0] == expected_mime
                    and "attachment" in lower_headers.get("content-disposition", ""),
                    "Delivered MIME/disposition differs from its format")
            require(delivered["body"] == server_bytes, "HTTP bytes differ from server temporary file")
            (folder / ("delivered." + fmt)).write_bytes(delivered["body"])
            result["delivered_file"] = dict(bytes=len(delivered["body"]), sha256=sha(delivered["body"]))
            result["server_temp_download_bytes_equal"] = True
            cleanup_deadline = min(self.deadline, time.monotonic() + 5)
            while Path(row["tmp"]).exists() and time.monotonic() < cleanup_deadline:
                time.sleep(0.05)
            require(not Path(row["tmp"]).exists(), "Downloaded temporary file was not cleaned")
            result["temporary_file_absent"] = True
            if delivered["will_close"] or reader.http.sock is None:
                reader.close()
                reader = self.acquire(consumer)
                result["post_cleanup_connection_reacquired"] = True
            for path in (status_path, download_path):
                after = reader.request("GET", path, self.owner, label=fmt + "_after_cleanup")
                require(after["status"] == 404, "Post-download owner endpoint did not return404")
            final_row = self.task_row(task)
            require(final_row == row, "Cleanup unexpectedly changed the terminal shared task row")
            result["terminal_row_retained"] = True
            reader.close()
            reader = None
            result["document_inspection"] = self.validate_document(fmt, delivered["body"], folder)
            result["success"] = True
        except BaseException as exc:
            result["error"] = type(exc).__name__ + ": " + str(exc)
            raise
        finally:
            if creator:
                creator.close()
            if reader:
                reader.close()
            write_json(folder / "case-result.json", result)
            self.save()

    def shutdown(self):
        end = time.monotonic() + SHUTDOWN_SECONDS
        cleanup = dict(started_utc=utc(), forced=False, remaining_processes=[])
        self.receipt["shutdown"] = cleanup
        for channel in self.channels:
            try:
                channel.close()
            except OSError as exc:
                cleanup.setdefault("channel_close_errors", []).append(str(exc))
        if self.master is None:
            cleanup.update(master_started=False, ended_utc=utc(), known_gunicorn_processes_ended=True)
            return
        cleanup["master_started"] = True
        graceful_end = end - 3
        try:
            if self.master.poll() is None:
                os.kill(self.master.pid, signal.SIGTERM)
                cleanup["signal"] = "SIGTERM to Gunicorn master"
            while time.monotonic() < graceful_end:
                self.master.poll()
                members = group_members(self.master.pid)
                if not members:
                    break
                time.sleep(0.1)
            members = group_members(self.master.pid)
            if members:
                cleanup["forced"] = True
                cleanup["before_force"] = members
                require(self.master.pid > 1 and self.master.pid != os.getpgrp(), "Unsafe process group")
                os.killpg(self.master.pid, signal.SIGKILL)
                while time.monotonic() < end and group_members(self.master.pid):
                    self.master.poll()
                    time.sleep(0.05)
            self.master.poll()
            cleanup["remaining_processes"] = group_members(self.master.pid)
            cleanup["master_exit_code"] = self.master.returncode
            known = dict(self.workers)
            if self.receipt.get("master_process"):
                known[self.master.pid] = self.receipt["master_process"]
            cleanup["known_pid_residue"] = [
                current for pid, before in known.items()
                if (current := proc(pid)) and current["start_ticks"] == before["start_ticks"]
            ]
            cleanup["known_gunicorn_processes_ended"] = (
                not cleanup["remaining_processes"] and not cleanup["known_pid_residue"])
            cleanup["proof_scope"] = "Owned process group and recorded native master/worker PIDs; not an adversarial escape-containment claim"
        except BaseException as exc:
            cleanup["error"] = type(exc).__name__ + ": " + str(exc)
            cleanup["known_gunicorn_processes_ended"] = False
        cleanup["ended_utc"] = utc()

    def scan_public_secrets(self):
        """Quarantine any matching raw file so always-upload cannot publish it."""
        tokens = [value.encode("utf-8") for value in self.known_secrets()]
        quarantined = []
        quarantine = self.private / "quarantined-public-files"
        for path in sorted(self.evidence.rglob("*")):
            if not path.is_file():
                continue
            require(time.monotonic() < self.deadline, "Public secret scan budget expired")
            data = path.read_bytes()
            if any(token in data for token in tokens):
                relative = path.relative_to(self.evidence)
                destination = quarantine / relative
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                path.replace(destination)
                quarantined.append(dict(path=str(relative), bytes=len(data), sha256=sha(data),
                                        cause="known_secret_match"))
        self.receipt["public_evidence_secret_scan"] = dict(
            passed=not quarantined, known_values_checked=len(tokens), quarantined=quarantined,
            method="Literal matching of every observed password/admin secret/CSRF/session-cookie value; raw matches moved outside public evidence")

    def execute(self):
        def interrupted(signum, frame):
            raise VerificationFailure("Supervisor interrupted by signal" + str(signum))
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        signal.signal(signal.SIGALRM, interrupted)
        signal.setitimer(signal.ITIMER_REAL, TOTAL_SECONDS)
        try:
            self.preflight()
            self.start()
            self.seed_and_login()
            a, b = sorted(self.workers)
            self.case("docx", a, b)
            self.case("pdf", b, a)
            self.check_pool()
            self.receipt["positive_checks_completed"] = True
        except BaseException as exc:
            self.receipt["failure"] = dict(phase=self.receipt["phase"],
                                           type=type(exc).__name__, message=str(exc))
            (self.evidence / "failure-traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            # Persistence failure must never prevent termination of the server.
            self.receipt["phase"] = "shutdown"
            try:
                self.save()
            except BaseException as exc:
                self.receipt["checkpoint_error"] = type(exc).__name__ + ": " + str(exc)
            finally:
                self.shutdown()
            # Configured phase budgets: active900 + shutdown30 + postflight30.
            # Quarantine recovery and final receipt writes are small additional
            # overhead; the workflow's 17-minute step is the outer time cap.
            self.deadline = time.monotonic() + POSTFLIGHT_SECONDS
            signal.setitimer(signal.ITIMER_REAL, POSTFLIGHT_SECONDS)
            try:
                try:
                    after, _ = self.source_snapshot()
                    write_json(self.evidence / "source-after.json", after)
                    require(after == self.receipt.get("source_before"), "Source/font changed during native run")
                    self.receipt["source_after"] = after
                    self.receipt["source_preserved"] = True
                except BaseException as exc:
                    self.receipt["postflight_error"] = type(exc).__name__ + ": " + str(exc)
                require(time.monotonic() < self.deadline, "Read-only postflight budget expired")
                self.events.read()
                self.scan_public_secrets()
            except BaseException as exc:
                # A timeout or unreadable public file must not reach the
                # workflow's always-upload. Quarantine the directory without
                # reading its contents; publish only the sanitized receipt.
                signal.setitimer(signal.ITIMER_REAL, 0)
                self.receipt["postflight_error"] = type(exc).__name__ + ": " + str(exc)
                destination = self.private / "quarantined-uninspected-evidence"
                self.evidence.replace(destination)
                self.evidence.mkdir()
                self.receipt["public_evidence_secret_scan"] = dict(
                    passed=False, whole_evidence_quarantined=True,
                    reason="Postflight timeout/read/scan failure; no uninspected evidence is publishable")
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
            self.receipt["success"] = bool(
                self.receipt.get("positive_checks_completed") and self.receipt.get("source_preserved")
                and not self.receipt.get("failure") and not self.receipt.get("postflight_error")
                and self.receipt["shutdown"].get("known_gunicorn_processes_ended")
                and self.receipt["shutdown"].get("master_exit_code") == 0
                and not self.receipt["shutdown"].get("forced")
                and self.receipt["public_evidence_secret_scan"]["passed"]
                and not self.receipt.get("checkpoint_error"))
            self.receipt["phase"] = "completed" if self.receipt["success"] else "failed"
            self.receipt["ended_utc"] = utc()
            self.receipt["scope_limits"] = [
                "One master/two stable worker processes on one Linux host and shared SQLite/filesystem.",
                "Two real async exports with opposite worker delivery; no synthetic pending/error rows.",
                "Only localhost bind, logs and lifecycle/request observer hooks overlay production config.",
                "Document parsing/marker extraction is not visual QA or F003 closure.",
                "No native individual worker exit codes are claimed; master exit/group absence are recorded.",
            ]
            self.save()
        return 0 if self.receipt["success"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--run-root", required=True, type=Path)
    args = parser.parse_args()
    return Run(args.source, args.run_root).execute()


if __name__ == "__main__":
    raise SystemExit(main())
