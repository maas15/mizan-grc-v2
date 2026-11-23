"""Exercise the actual saved PDF routes with the immutable Contract R source."""
import os
from pathlib import Path

import pytest

from mizan_correction_support import case, client_for, post, update_row, wait_terminal


def owner_pdf(app, client, payload, transport):
    path = '/api/generate-pdf' + ('-async' if transport == 'async' else '')
    reply = post(client, path, payload)
    assert reply.status_code == 200, reply.get_json(silent=True)
    if transport == 'sync':
        return reply
    task = reply.json['task_id']
    ready = wait_terminal(client, task)
    assert ready.json.get('status') == 'done', ready.json
    other = client_for(app, 8)
    for verb in ('export-status', 'export-download'):
        denied = other.get(f'/api/{verb}/{task}')
        assert denied.status_code == 403 and denied.json['reason'] == 'export_task_not_owned'
    result = client.get('/api/export-download/' + task, buffered=True)
    assert result.status_code == 200
    assert client.get('/api/export-status/' + task).status_code == 404
    return result


@pytest.mark.parametrize('transport', ['sync', 'async'])
def test_saved_pdf_fresh_reuse_and_mutation(case, transport):
    app, frozen, body, sections, payload = case
    path = '/api/generate-pdf' + ('-async' if transport == 'async' else '')
    # Forged fidelity and internal route fields must not select a source or bypass the binder.
    payload = dict(payload, artifact_type='gap_assessment', document_type='gap_assessment')
    assert post(client_for(app, 8), path, payload).status_code == 403
    client = client_for(app)
    bad_alias = dict(payload, strategy_id='invalid-id', _saved_pdf_fidelity={'route': 'pdf'})
    assert post(client, path, bad_alias).status_code == 422
    output = Path(os.environ['DATABASE_PATH']).parent
    # The fixture uses a temporary DB; keep deliveries with the external launcher evidence.
    output = Path(os.environ.get('MIZAN_PDF_OUTPUT', output))
    output.mkdir(exist_ok=True, parents=True)
    expected = frozen._load_pair(702)[1]
    for phase in ('fresh','reuse'):
        if phase == 'reuse':
            payload.update(_saved_pdf_fidelity={'route':'pdf'}, skip_rel26_gate=True)
            updated = dict(reversed(list(frozen._sections_for_row(sections).items())))
            update_row(app, body, updated)
        reply = owner_pdf(app, client, payload, transport)
        assert reply.mimetype == 'application/pdf' and 'attachment' in reply.headers['Content-Disposition']
        (output / f'702-{transport}-{phase}.pdf').write_bytes(reply.data)
        if phase == 'fresh':
            current = frozen.canon._ARTIFACT_REGISTRY['702']
        assert frozen.canon._ARTIFACT_REGISTRY['702'] is current
        assert current.final_markdown_view == body
        verify_delivery(reply.data, body, expected, output, transport+'-'+phase)
    before, after = 'ترى أمانة الواحة', 'تؤكد أمانة الواحة'
    assert before in sections['vision'] and before in body
    update_row(app, body.replace(before, after, 1),
               dict(updated, vision=sections['vision'].replace(before, after, 1)))
    refused = post(client, path, payload)
    if transport == 'sync':
        assert refused.status_code == 422 and any('frozen_' in x for x in refused.json['blocking_errors'])
    else:
        assert refused.status_code == 200
        failed = wait_terminal(client, refused.json['task_id'])
        assert failed.status_code >= 400


@pytest.mark.parametrize('transport', ['sync','async'])
def test_invalid_saved_pdf_refused_before_writer(case, transport, monkeypatch):
    app, frozen, _, _, _ = case
    text, expected, sections, _, _ = frozen._load_pair(701)
    frozen._insert(701, expected, text, sections)
    client = client_for(app)
    payload = frozen._payload(701, expected)
    writes = []
    from release_engine_v3.exporters import saved_strategy_pdf
    render = saved_strategy_pdf.render_saved_pdf
    def observe(*args, **kwargs):
        writes.append(True)
        return render(*args, **kwargs)
    monkeypatch.setattr(saved_strategy_pdf, 'render_saved_pdf', observe)
    result = post(client, '/api/generate-pdf' + ('-async' if transport=='async' else ''), payload)
    if transport == 'sync':
        assert result.status_code == 422
        assert 'rel3_generation_contract_failed:objectives' in result.json['blocking_errors']
    else:
        assert result.status_code == 200
        assert wait_terminal(client, result.json['task_id']).status_code >= 400
    assert not writes


def verify_delivery(data, body, expected, output, label):
    from release_engine_v3.exporters.saved_pdf_verification import verify_saved_pdf
    import json
    import re
    from release_engine_v3.canonical_document import parse_saved_markdown_structure
    blocks, error = parse_saved_markdown_structure(body)
    assert not error
    tables = [b for b in blocks if b['kind'] == 'table']
    for authored, parsed in zip(expected['tables'].values(), tables, strict=True):
        assert parsed['header'] == authored['header']
        assert parsed['rows'] == authored['rows']
    assert len(expected['tables']['roadmap']['rows']) == 10
    assert len(expected['tables']['kpis']['rows']) == 5
    assert len(set(re.findall(r'\b[A-Z]+-DT-POS-\d{2}\b', body))) == 31
    assert body.count('(API v2.1)') == 12 and '82 من 100' in body
    result = verify_saved_pdf(data, body, retain_cells=True)
    # A KPI target is meaningful only in its source row. Keep the same token in the
    # document elsewhere and require rejection of the altered source expectation.
    if label == 'sync-fresh':
        row = next(line for line in body.splitlines() if line.startswith('| KPI-DT-POS-01 |'))
        altered = body.replace(row, row.replace('99.5%', '98.5%'))
        assert altered != body and '99.5%' in altered
        with pytest.raises(ValueError):
            verify_saved_pdf(data, altered)
    assert result['sections'] == len(expected['section_order'])
    (output / ('content-'+label+'.json')).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf8')
