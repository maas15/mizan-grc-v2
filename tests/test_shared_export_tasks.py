"""Exercise export handoff between interpreters with shared SQLite and temp storage."""
from contextlib import closing
from io import BytesIO
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import uuid

from mizan_correction_support import case, client_for, post, wait_terminal


def _read_in_second_process(tasks):
    sys.path.insert(0, str(Path.cwd()))
    import app
    assert not app._export_store
    owner, other = client_for(app), client_for(app, 8)
    for fmt, task in tasks.items():
        status = "/api/export-status/" + task
        download = "/api/export-download/" + task
        own = owner.get(status)
        assert own.status_code == 200 and own.json["status"] == "done", (fmt, own.status_code, own.json)
        assert other.get(status).status_code == 403
        assert other.get(download).status_code == 403
        response = owner.get(download, buffered=True)
        assert response.status_code == 200 and "attachment" in response.headers["Content-Disposition"]
        assert response.data.startswith(b"PK" if fmt == "docx" else b"%PDF")
        assert response.mimetype == ("application/pdf" if fmt == "pdf" else
                                     "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        response.close()
        assert owner.get(download).status_code == 404
        assert owner.get(status).status_code == 404
    print(json.dumps({"reader_pid": os.getpid(), "writer_pid": os.getppid(), "formats": list(tasks)}))


def test_export_between_processes(case, monkeypatch):
    app, frozen, text, sections, payload = case
    client = client_for(app)
    # The PDF renderer alone is substituted. The route, actual worker, file write,
    # store, authorization, download and close callback remain production code.
    from reportlab.pdfgen.canvas import Canvas
    from flask import Response
    def small_pdf():
        stream = BytesIO()
        canvas = Canvas(stream)
        canvas.drawString(50, 700, "Cross-process verification")
        canvas.save()
        return Response(stream.getvalue(), mimetype="application/pdf")
    monkeypatch.setattr(app, "api_generate_pdf", small_pdf)
    tasks = {}
    for fmt in ("docx", "pdf"):
        data = dict(payload, content=text, domain="Digital Transformation", language="ar",
                    doc_type="strategy", generation_mode="consulting")
        queued = post(client, "/api/generate-" + fmt + "-async", data)
        assert queued.status_code == 200, (fmt, queued.status_code, queued.json)
        task = queued.json["task_id"]
        terminal = wait_terminal(client, task)
        assert terminal.json.get("status") == "done", (fmt, terminal.json)
        tasks[fmt] = task
    cmd = [sys.executable, "-B", str(Path(__file__).resolve()), json.dumps(tasks)]
    print("producer_pid", os.getpid(), "reader_command", cmd)
    result = subprocess.run(cmd, capture_output=True, timeout=100)
    print(result.stdout.decode("utf-8", "replace"))
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def test_nonterminal_download_and_storage_failures(case, tmp_path, monkeypatch):
    app, *_ = case
    client = client_for(app)
    decoy = tmp_path / "never-stream.pdf"
    decoy.write_bytes(b"not a completed export")
    with closing(app.get_db_direct()) as conn, conn:
        for state in ("pending", "error", "done"):
            task = str(uuid.uuid4())
            file = str(decoy) if state != "done" else str(tmp_path / "missing.pdf")
            conn.execute("INSERT INTO export_tasks(task_id,user_id,fmt,filename,status,tmp) VALUES (?,?,?,?,?,?)",
                         (task, 7, "pdf", "sample", state, file))
            conn.commit()
            assert client.get("/api/export-download/" + task).status_code == 404
            assert client.get("/api/export-status/" + task).status_code == {"pending":200, "error":500, "done":404}[state]
    assert decoy.read_bytes() == b"not a completed export"
    def unavailable():
        raise sqlite3.OperationalError("simulated store outage")
    monkeypatch.setattr(app, "get_db_direct", unavailable)
    with app.app.test_request_context():
        task = str(uuid.uuid4())
        ran = []
        response, code = app._start_export_task(task, "pdf", "test", 7, None, lambda: ran.append(True))
        assert code == 503 and "task_id" not in response.json and task not in app._export_store and not ran


if __name__ == "__main__":
    _read_in_second_process(json.loads(sys.argv[1]))
