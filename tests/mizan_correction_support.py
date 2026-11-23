"""Disposable state for the integration regressions."""
from contextlib import closing
import json
from pathlib import Path
import time

import pytest


@pytest.fixture
def case(tmp_path, monkeypatch):
    db = str(tmp_path / "app.db")
    for key in ("DATABASE_PATH", "MIZAN_DOCX_DATABASE_PATH"):
        monkeypatch.setenv(key, db)
    for key in ("TEMP", "TMP", "TMPDIR"):
        monkeypatch.setenv(key, str(tmp_path))
    monkeypatch.setenv("SECRET_KEY", "synthetic-correction-key")
    monkeypatch.setenv("ADMIN_PASSWORD", "synthetic-correction-admin")
    monkeypatch.syspath_prepend(str(Path.cwd() / "tests"))
    import app
    import test_docx_contract_r_positive_02 as frozen
    monkeypatch.setattr(app.config, "DB_PATH", db)
    app.init_db()
    text, expected, sections, _, _ = frozen._load_pair(702)
    frozen._insert(702, expected, text, sections)
    frozen.canon._ARTIFACT_REGISTRY.pop("702", None)
    yield app, frozen, text, sections, frozen._payload(702, expected)
    frozen.canon._ARTIFACT_REGISTRY.pop("702", None)


def client_for(app, owner=7):
    client = app.app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = owner
        session["csrf_token"] = "correction-fixture-csrf"
    return client


def post(client, endpoint, data):
    return client.post(endpoint, buffered=True, json=data, headers={"X-CSRFToken": "correction-fixture-csrf"})


def update_row(app, text, sections):
    with closing(app.get_db_direct()) as conn, conn:
        conn.execute("UPDATE strategies SET content=?,sections_json=? WHERE id=702 AND user_id=7",
                     (text, json.dumps(sections, ensure_ascii=False)))


def wait_terminal(client, task_id):
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        response = client.get("/api/export-status/" + task_id)
        state = response.get_json().get("status")
        if state != "pending":
            return response
        time.sleep(0.03)
    pytest.fail("export worker exceeded 75 seconds")
