"""Observation-only overlay. The supervisor sets these paths for one local run."""
import hashlib as _hashlib
import json as _json
import os as _os
from pathlib import Path as _Path
import sys as _sys
import time as _time
from datetime import datetime as _datetime, timezone as _timezone

_source = _Path(_os.environ["MIZAN_NATIVE_SOURCE_ROOT"]).resolve()
_evidence = _Path(_os.environ["MIZAN_NATIVE_OBSERVER_DIR"]).resolve()
_production_path = _source / "gunicorn_config.py"
_production_bytes = _production_path.read_bytes()
if _hashlib.sha256(_production_bytes).hexdigest() != "974fb69b1febaef61b01217d31663fb6003cef2fcaa45a34c96c0ec051211dfe":
    raise RuntimeError("Production Gunicorn configuration identity mismatch")
_production = {}
exec(compile(_production_bytes, str(_production_path), "exec"), _production)
_expected_core = {
    "workers": 2, "threads": 4, "timeout": 600, "keepalive": 5,
    "max_requests": 1000, "max_requests_jitter": 100, "preload_app": False,
}
for _key, _value in _expected_core.items():
    if _production.get(_key) != _value:
        raise RuntimeError("Unexpected production setting: " + _key)
globals().update({key: value for key, value in _production.items() if not key.startswith("__")})

# Application, worker settings and renderer are unchanged. Only local binding
# and observation settings differ from the verified production configuration.
bind = "127.0.0.1:" + _os.environ["MIZAN_NATIVE_PORT"]
accesslog = str(_evidence / "gunicorn-access.log")
errorlog = str(_evidence / "gunicorn-error.log")
access_log_format = (
    "pid=%(p)s request_id=%({x-mizan-probe-id}i)s method=%(m)s "
    "path=%(U)s status=%(s)s bytes=%(B)s duration_us=%(D)s"
)


def _emit(kind, **values):
    event = {
        "event": kind, "pid": _os.getpid(), "ppid": _os.getppid(),
        "pgid": _os.getpgrp(), "monotonic": _time.monotonic(),
        "utc": _datetime.now(_timezone.utc).isoformat(), **values,
    }
    data = (_json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    fd = _os.open(str(_evidence / ("observer-" + str(_os.getpid()) + ".jsonl")),
                  _os.O_WRONLY | _os.O_CREAT | _os.O_APPEND, 0o600)
    try:
        if _os.write(fd, data) != len(data):
            raise OSError("Incomplete observer event write")
    finally:
        _os.close(fd)


def _core(cfg):
    result = {key: getattr(cfg, key) for key in _expected_core}
    result["bind"] = cfg.bind
    result["graceful_timeout"] = cfg.graceful_timeout
    return result


def on_starting(server):
    _emit("master_start", production_bind=_production["bind"], effective=_core(server.cfg))


def when_ready(server):
    _emit("master_ready", effective=_core(server.cfg))


def post_fork(server, worker):
    _emit("worker_fork", worker_pid=worker.pid)


def post_worker_init(worker):
    module = _sys.modules.get("app")
    _emit("worker_initialized", effective=_core(worker.cfg),
          worker_class=type(worker).__module__ + "." + type(worker).__name__,
          app_module_path=getattr(module, "__file__", None),
          database_path=_os.environ.get("DATABASE_PATH"))


def _request_fields(req):
    request_id = next((value for key, value in req.headers
                       if key.lower() == "x-mizan-probe-id"), None)
    return {"request_id": request_id, "method": req.method, "path": req.path}


def pre_request(worker, req):
    _emit("request_start", **_request_fields(req))


def post_request(worker, req, environ, resp):
    _emit("request_end", status=str(getattr(resp, "status", "")), **_request_fields(req))


def worker_exit(server, worker):
    _emit("worker_exit", worker_pid=worker.pid)


def child_exit(server, worker):
    _emit("master_observed_child_exit", worker_pid=worker.pid)


def on_exit(server):
    _emit("master_exit")
