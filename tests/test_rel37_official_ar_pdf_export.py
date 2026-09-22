"""Official Data/AI/DT AR PDF export on the compiled live hashes.

Test-owned compiled sources match the official live model hashes. They
are not the private staging UUIDs. Evidence stays enabled. The public
async worker/status/download path is exercised with a real thread.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_ENV_KEYS = (
    'ADMIN_PASSWORD', 'SECRET_KEY', 'DATABASE_PATH', 'DATABASE_URL',
    'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY',
    'REL2_SKIP_EXPORT_EVIDENCE', 'REL37_DATA_AI_DT_COMPILER',
)
os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)
_ENV_BEFORE = {key: os.environ.get(key) for key in _ENV_KEYS}
_TMP = tempfile.mkdtemp(prefix='test_rel37_official_ar_pdf_')


def _ensure_test_env():
    os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)
    os.environ['ADMIN_PASSWORD'] = 'test-admin-password'
    os.environ['SECRET_KEY'] = 'test-secret-key'
    os.environ.setdefault('DATABASE_PATH', os.path.join(_TMP, 'official_ar.db'))
    os.environ.setdefault(
        'DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'official_ar.db'))
    os.environ['OPENAI_API_KEY'] = ''
    os.environ['ANTHROPIC_API_KEY'] = ''
    os.environ['GOOGLE_API_KEY'] = ''
    os.environ['REL37_DATA_AI_DT_COMPILER'] = '1'


_ensure_test_env()

import app as app_mod  # noqa: E402

from release_engine_v3.rel37_apply import (  # noqa: E402
    REL37_APPLIED_KEY,
    REL37_CANONICAL_FW_KEY,
    REL37_HASH_KEY,
    REL37_MODEL_KEY,
    REL37_ORIGINAL_FW_KEY,
    REL37_SELECTION_REASON_KEY,
    REL37_SELECTION_SUPPORTED_KEY,
    serialize_model,
)
from release_engine_v3.rel37_compilers import compile_for_domain  # noqa: E402
from release_engine_v3.rel37_export_content_parity import (  # noqa: E402
    _mixed_script_runs,
    _paragraph_pdf_blockers,
    _undo_visual_rtl_line,
    compare_environment_narrative_to_pdf,
    environment_narrative_paragraphs,
)
from release_engine_v3.rel37_render import model_to_markdown, model_to_sections  # noqa: E402

LIVE_HASHES = {
    'data': '50de805c4b3b620c47eec08205bc01168652aed89cfb01d032ee144cb098b742',
    'ai': 'e73e78299f409a9d23a82491cbbee008c7ae1bd26f6e8e7502ccb0332c410ca4',
    'dt': '9abdb2f6e675315ea4a534b9cf72e598d2fd632155a8f22942f49aeb8a733551',
}
_CASES = (
    ('data', 'Data Management', 'REL33 P1 Data Management Org',
     'Government', ['NDMO', 'PDPL']),
    ('ai', 'Artificial Intelligence', 'REL33 P1 Artificial Intelligence Org',
     'Government', ['SDAIA']),
    ('dt', 'Digital Transformation', 'REL33 P1 Digital Transformation Org',
     'Government', ['DGA']),
)
_UID = {'n': 1200}


def tearDownModule():
    for key, previous in _ENV_BEFORE.items():
        if previous is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = previous


def _compile(domain, org, sector, fws):
    return compile_for_domain(domain, {
        'domain': domain,
        'lang': 'ar',
        'org_name': org,
        'sector': sector,
        'document_type': 'strategy',
        'selected_frameworks': fws,
    })


def _sections(model):
    sections = model_to_sections(model)
    sections[REL37_APPLIED_KEY] = '1'
    sections[REL37_MODEL_KEY] = serialize_model(model)
    sections[REL37_HASH_KEY] = model.model_hash
    sections[REL37_SELECTION_SUPPORTED_KEY] = 'true'
    sections[REL37_SELECTION_REASON_KEY] = 'supported_selection'
    sections[REL37_CANONICAL_FW_KEY] = list(model.selected_frameworks)
    sections[REL37_ORIGINAL_FW_KEY] = list(model.selected_frameworks)
    return sections


def _persist(model, *, domain_label, role='user'):
    _UID['n'] += 1
    uid = _UID['n']
    username = f'offar{uid}'
    sections = _sections(model)
    content = model_to_markdown(model)
    with app_mod.app.app_context():
        db = app_mod.get_db()
        db.execute(
            'INSERT OR IGNORE INTO users '
            '(id, username, password_hash, role, is_active) '
            'VALUES (?, ?, ?, ?, 1)',
            (uid, username, 'x', role),
        )
        cur = db.execute(
            'INSERT INTO strategies '
            '(user_id, domain, org_name, sector, content, language, '
            ' document_title, sections_json, content_json) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                uid, domain_label, model.org_name, model.sector or 'Government',
                content, model.lang, 'official ar pdf',
                json.dumps(sections, ensure_ascii=False),
                json.dumps({'sections': sections}, ensure_ascii=False),
            ),
        )
        sid = cur.lastrowid
        db.commit()
    client = app_mod.app.test_client()
    csrf = f'offar-{uid}'
    with client.session_transaction() as sess:
        sess['user_id'] = uid
        sess['username'] = username
        sess['role'] = role
        sess['csrf_token'] = csrf
    return {
        'uid': uid,
        'role': role,
        'client': client,
        'headers': {'X-CSRFToken': csrf, 'Content-Type': 'application/json'},
        'strategy_id': sid,
        'model': model,
        'content': content,
        'domain': domain_label,
    }


def _official_body(saved, *, fws):
    return {
        'content': saved['content'],
        'filename': 'rel33_official',
        'language': 'ar',
        'org_name': saved['model'].org_name,
        'sector': 'Government',
        'doc_type': 'Strategy Document',
        'domain': saved['domain'],
        'selected_frameworks': fws,
        'artifact_type': 'strategy',
        'document_type': 'strategy',
        'generation_mode': 'drafting',
        'strategy_id': saved['strategy_id'],
        'artifact_id': saved['strategy_id'],
    }


def _export(saved, body, fmt):
    payload = dict(body)
    payload.setdefault('document_type', 'strategy')
    payload.setdefault('artifact_type', 'strategy')
    payload.setdefault('generation_mode', 'drafting')
    payload['strategy_id'] = saved['strategy_id']
    payload['artifact_id'] = saved['strategy_id']
    resp = saved['client'].post(
        f'/api/generate-{fmt}-async', json=payload, headers=saved['headers'])
    submit = resp.get_json(silent=True) or {}
    tid = submit.get('task_id')
    status = {}
    raw = b''
    download_http = 0
    if tid:
        deadline = time.time() + 90
        while time.time() < deadline:
            status = saved['client'].get(
                f'/api/export-status/{tid}', headers=saved['headers']
            ).get_json(silent=True) or {}
            if status.get('status') in ('done', 'error'):
                break
            time.sleep(0.2)
        if status.get('status') == 'done':
            dl = saved['client'].get(
                f'/api/export-download/{tid}', headers=saved['headers'])
            download_http = dl.status_code
            raw = dl.data or b''
    return {
        'submit_http': resp.status_code,
        'submit': submit,
        'status': status,
        'download_http': download_http,
        'bytes': raw,
        'task_id': tid,
    }


class OfficialMixedScriptRunTests(unittest.TestCase):
    def test_latin_org_phrase_stays_one_run(self):
        line = (
            'في سياق تشغيلي لقطاع حكومي، ضمن بيئة تنظيمية تتطلب حوكمة'
            'REL33 P1 Data Management Org تعمل')
        runs = _mixed_script_runs(line)
        self.assertIn('REL33 P1 Data Management Org', runs)
        undone = _undo_visual_rtl_line(line)
        self.assertTrue(undone.lstrip().startswith('تعمل'))
        self.assertIn('REL33 P1 Data Management Org', undone)
        self.assertIn('في سياق', undone)
        self.assertLess(undone.find('تعمل'), undone.find('REL33'))
        self.assertLess(undone.find('REL33'), undone.find('في سياق'))

    def test_swapped_latin_still_refused(self):
        para = (
            'تعمل REL33 P1 Data Management Org في سياق تشغيلي لقطاع حكومي، '
            'ضمن بيئة تنظيمية تتطلب حوكمة بيانات وطنية وفق NDMO وحماية '
            'بيانات شخصية وفق PDPL، مع ضغط متزايد على جودة البيانات.')
        swapped = para.replace('NDMO', 'PDPL_HOLD').replace(
            'PDPL', 'NDMO').replace('PDPL_HOLD', 'PDPL')
        blockers = _paragraph_pdf_blockers(
            0, para, swapped, visible=swapped, actual=swapped)
        self.assertTrue(blockers, blockers)

    def test_actual_text_only_still_unestablished(self):
        para = (
            'تعمل REL33 P1 Data Management Org في سياق تشغيلي لقطاع حكومي، '
            'ضمن بيئة تنظيمية تتطلب حوكمة بيانات وطنية وفق NDMO.')
        blockers = _paragraph_pdf_blockers(
            0, para, para, visible='', actual=para)
        self.assertIn('pdf_environment_painted_unestablished:0', blockers)

    def test_cut_paragraph_still_refused(self):
        para = (
            'تعمل REL33 P1 Data Management Org في سياق تشغيلي لقطاع حكومي، '
            'ضمن بيئة تنظيمية تتطلب حوكمة بيانات وطنية وفق NDMO وحماية '
            'بيانات شخصية وفق PDPL، مع ضغط متزايد على جودة البيانات.')
        cut = ' '.join(para.split()[:-6])
        blockers = _paragraph_pdf_blockers(
            0, para, cut, visible=cut, actual=para)
        self.assertTrue(blockers, blockers)


class OfficialArPdfExportTests(unittest.TestCase):
    def setUp(self):
        _ensure_test_env()

    def test_compiled_hashes_match_official_live(self):
        for domain, _label, org, sector, fws in _CASES:
            model = _compile(domain, org, sector, fws)
            self.assertEqual(model.model_hash, LIVE_HASHES[domain], domain)

    def test_official_data_ai_dt_async_pdf_done(self):
        for domain, label, org, sector, fws in _CASES:
            model = _compile(domain, org, sector, fws)
            saved = _persist(model, domain_label=label)
            official = _export(saved, _official_body(saved, fws=fws), 'pdf')
            self.assertEqual(official['submit_http'], 200, official['status'])
            self.assertEqual(
                official['status'].get('status'), 'done', official['status'])
            self.assertEqual(official['download_http'], 200, official['status'])
            self.assertTrue(
                official['bytes'].startswith(b'%PDF'), official['status'])
            self.assertEqual(
                compare_environment_narrative_to_pdf(model, official['bytes']),
                [], domain)
            paras = environment_narrative_paragraphs(model.environment_narrative)
            self.assertTrue(paras)
            self.assertIn('Government', model.sector or 'Government')

    def test_data_official_ui_saved_id_and_warm_order(self):
        domain, label, org, sector, fws = _CASES[0]
        model = _compile(domain, org, sector, fws)
        saved = _persist(model, domain_label=label)
        official = _export(saved, _official_body(saved, fws=fws), 'pdf')
        ui_body = dict(_official_body(saved, fws=fws))
        ui_body['org_name'] = model.org_name
        ui = _export(saved, ui_body, 'pdf')
        sid_body = {
            'filename': 'saved_id',
            'language': 'ar',
            'domain': label,
            'doc_type': 'Strategy Document',
            'document_type': 'strategy',
            'artifact_type': 'strategy',
            'generation_mode': 'drafting',
            'strategy_id': saved['strategy_id'],
            'artifact_id': saved['strategy_id'],
        }
        sid = _export(saved, sid_body, 'pdf')
        for label_n, result in (
                ('official', official), ('ui', ui), ('saved_id', sid)):
            self.assertEqual(
                result['status'].get('status'), 'done', (label_n, result['status']))
            self.assertTrue(
                result['bytes'].startswith(b'%PDF'), (label_n, result['status']))
            self.assertEqual(
                compare_environment_narrative_to_pdf(model, result['bytes']),
                [], label_n)

    def test_admin_role_equivalent_content_still_gated(self):
        domain, label, org, sector, fws = _CASES[0]
        model = _compile(domain, org, sector, fws)
        saved = _persist(model, domain_label=label, role='admin')
        result = _export(saved, _official_body(saved, fws=fws), 'pdf')
        self.assertEqual(result['status'].get('status'), 'done', result['status'])
        self.assertTrue(result['bytes'].startswith(b'%PDF'), result['status'])
        self.assertEqual(
            compare_environment_narrative_to_pdf(model, result['bytes']), [])


if __name__ == '__main__':
    unittest.main()
