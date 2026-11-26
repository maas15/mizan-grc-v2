"""Saved Arabic DT type dispatch and the identity of the freshly frozen artifact."""
from contextlib import closing
import json

from mizan_correction_support import case, client_for, post, update_row, wait_terminal


def test_gap_native_routes(case, monkeypatch):
    app, frozen, _, _, payload = case
    gap = {"_document_type":"gap_assessment", "scope":"نطاق التقييم ISO 27001",
           "gaps":"| المعرف | الفجوة |\n|---|---|\n| GAP-1 | الرقابة |",
           "remediation":"| العمل | المالك |\n|---|---|\n| تنفيذ الرقابة | المدير |"}
    text = "\n\n".join(gap[k] for k in ("scope", "gaps", "remediation"))
    update_row(app, text, gap)
    with closing(app.get_db_direct()) as conn, conn:
        conn.execute("UPDATE strategies SET content_json=? WHERE id=702 AND user_id=7",
                     (json.dumps({"document_type": "gap_assessment"}),))
    client = client_for(app)
    calls = []
    prepare = app._rel33_prepare_gap_assessment_export_content
    def observe(*args, **kwargs):
        result = prepare(*args, **kwargs)
        calls.append((kwargs["route"], result["diag"]["loaded_from"], result["content"]))
        return result
    monkeypatch.setattr(app, "_rel33_prepare_gap_assessment_export_content", observe)
    for suffix in ("", "-async"):
        calls.clear()
        data = dict(payload, content=text, domain="Digital Transformation", language="ar",
                    artifact_type="gap_assessment", document_type="gap_assessment")
        if suffix:
            data.update(artifact_type="strategy", document_type="strategy")
        denied = post(client_for(app, 8), "/api/generate-docx" + suffix, data)
        assert denied.status_code == 403 and not calls
        response = post(client, "/api/generate-docx" + suffix, data)
        assert response.status_code == 200, response.get_json(silent=True)
        if suffix:
            task = response.json["task_id"]
            assert wait_terminal(client, task).json["status"] == "done"
            delivered = client.get("/api/export-download/" + task, buffered=True)
            assert delivered.status_code == 200 and delivered.data.startswith(b"PK")
        else:
            assert response.data.startswith(b"PK")
        assert calls, (suffix, response.status_code, response.get_json(silent=True))
        assert calls[0][1] == "gap_assessment_sections_json" and "GAP-1" in calls[0][2]


def test_stored_strategy_binding_and_owner(case):
    app, frozen, _, _, payload = case
    data = dict(payload, artifact_type="gap_assessment", document_type="gap_assessment")
    with app.app.test_request_context():
        from flask import session
        session["user_id"] = 7
        bound = app._docx_saved_reference_dispatch(data)
        assert bound["kind"] == "arabic_dt" and bound["document_type"] == "strategy"
        assert bound["content"] != data["content"]
    other = client_for(app, 8)
    for endpoint in ("/api/generate-docx", "/api/generate-docx-async"):
        response = post(other, endpoint, data)
        assert response.status_code == 403 and response.json["reason"] == "owned_strategy_absent"


def test_reordered_fresh_then_reuse(case, monkeypatch):
    app, frozen, body, sections, payload = case
    reverse = dict(reversed(list(frozen._sections_for_row(sections).items())))
    update_row(app, body, reverse)
    client = client_for(app)
    canon = frozen.canon
    calls = []
    check = canon.saved_frozen_source_refusal
    def observe(artifact, obj):
        result = check(artifact, obj)
        calls.append((obj, result))
        return result
    monkeypatch.setattr(canon, "saved_frozen_source_refusal", observe)
    first = post(client, "/api/generate-docx", payload)
    assert first.status_code == 200 and first.data.startswith(b"PK"), first.get_json(silent=True)
    obj = canon._ARTIFACT_REGISTRY["702"]
    assert not calls
    second = post(client, "/api/generate-docx", payload)
    assert second.status_code == 200 and second.data.startswith(b"PK"), (second.get_json(silent=True), [r for _,r in calls])
    assert len(calls) == 1 and calls[0][0] is obj and calls[0][1] == ""
    assert obj.final_markdown_view == body
    changed = sections["vision"] + "\n\nتغيير معتمد في المصدر."
    update_row(app, body.replace(sections["vision"], changed, 1), dict(reverse, vision=changed))
    result = post(client, "/api/generate-docx", payload)
    assert result.status_code == 422 and calls[-1][0] is obj
    assert calls[-1][1].startswith("saved_docx_fidelity_refused:") and calls[-1][1] in result.json["blocking_errors"]
