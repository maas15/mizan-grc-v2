"""Official Data/AI/DT AR PDF export on the compiled live hashes.

Test-owned compiled sources match the official live model hashes. They
are not the private staging UUIDs. Evidence stays enabled. The public
async worker/status/download path is exercised with a real thread.
"""
from __future__ import annotations

import io
import json
import os
import re
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
    _arabic_leftover_rotation_of_actual,
    _content_words,
    _identifier_owns_digit_chip,
    _identity_digit_remnants,
    _is_identity_digit_remnant,
    _is_visual_leftover_run,
    _leftover_non_arabic_accounted,
    _mixed_script_runs,
    _paragraph_pdf_blockers,
    _undo_visual_rtl_line,
    compare_environment_narrative_to_pdf,
    environment_narrative_paragraphs,
    pdf_environment_section_text,
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


_NUMERIC_PARA = (
    'تطبق REL33 P1 Data Management Org ضوابط NDMO لمدة 10 سنوات وفق PDPL.'
)
_NUMERIC_PARA_REL88 = _NUMERIC_PARA.replace('REL33', 'REL88')
_NUMERIC_MUT_33 = _NUMERIC_PARA.replace('10 سنوات', '10.33 سنوات')
_NUMERIC_MUT_88 = _NUMERIC_PARA.replace('10 سنوات', '10.88 سنوات')
_EN_DASH = '\u2013'
_NUMERIC_RANGE_33 = _NUMERIC_PARA.replace('10 سنوات', f'10{_EN_DASH}33 سنوات')
_NUMERIC_RANGE_88 = _NUMERIC_PARA.replace('10 سنوات', f'10{_EN_DASH}88 سنوات')
_NUMERIC_RANGE_1_10 = _NUMERIC_PARA.replace('10 سنوات', f'1{_EN_DASH}10 سنوات')
_NUMERIC_RANGE_8_10 = _NUMERIC_PARA.replace('10 سنوات', f'8{_EN_DASH}10 سنوات')
_NUMERIC_PARA_P8 = _NUMERIC_PARA.replace('P1', 'P8')


def _true_framework_swap(para: str, left='NDMO', right='PDPL') -> str:
    mapping = {left: right, right: left}
    pattern = re.compile(
        r'\b(?:%s|%s)\b' % (re.escape(left), re.escape(right)))
    return pattern.sub(lambda match: mapping[match.group(0)], para)


def _assert_true_framework_swap(testcase, source, swapped, left='NDMO', right='PDPL'):
    intended = (
        source.replace(left, '\0L\0').replace(right, left).replace('\0L\0', right)
    )
    testcase.assertEqual(swapped, intended)
    testcase.assertEqual(swapped.count(left), source.count(right))
    testcase.assertEqual(swapped.count(right), source.count(left))
    testcase.assertNotIn('HOLD', swapped)
    testcase.assertNotIn('\x00', swapped)
    arabic_src = re.sub(r'[A-Za-z0-9._-]+', '', source)
    arabic_sw = re.sub(r'[A-Za-z0-9._-]+', '', swapped)
    testcase.assertEqual(arabic_src, arabic_sw)


def _numeric_env_pdf(visible: str, actual: str) -> bytes:
    """Test-owned readable PDF with independently painted vs ActualText."""
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfgen.canvas import Canvas

    font_path = '/usr/share/fonts/truetype/noto/NotoSansArabic-Regular.ttf'
    if font_path and 'ArabicFont' not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont('ArabicFont', font_path))
    buf = io.BytesIO()
    canv = Canvas(buf, pagesize=A4)
    canv.setFont('Helvetica', 10)
    canv.drawString(36, 800, 'Organization REL33 P1 Data Management Org')
    canv.drawString(36, 786, 'Sector Government')
    canv.showPage()
    y = 800
    canv.setFont('Helvetica', 10)
    canv.drawString(36, y, 'Business Environment and Drivers')
    y -= 16
    if actual:
        hex_actual = 'FEFF' + actual.encode('utf-16-be').hex().upper()
        canv._code.append('/Span << /ActualText <%s> >> BDC' % hex_actual)
    logical_paint = str(visible or '')
    if logical_paint:
        hex_text = 'FEFF' + logical_paint.encode('utf-16-be').hex().upper()
        canv._code.append(f'<{hex_text}> Tj')
    lines = str(visible or '').splitlines() or ['']
    for line in lines:
        latin = re.findall(r'[A-Za-z][A-Za-z0-9%._-]*', line)
        if latin:
            canv.setFont('Helvetica', 10)
            canv.drawString(36, y, ' '.join(latin))
            y -= 14
        arabic = re.sub(r'[A-Za-z0-9%._/-]+', ' ', line)
        if arabic.strip() and 'ArabicFont' in pdfmetrics.getRegisteredFontNames():
            canv.setFont('ArabicFont', 10)
            canv.drawRightString(560, y, arabic.strip())
            y -= 14
        elif arabic.strip():
            canv.setFont('Helvetica', 10)
            canv.drawString(36, y, arabic.strip())
            y -= 14
        nums = re.findall(r'\d+(?:\.\d+)?(?:\u2013\d+(?:\.\d+)?)?', line)
        if nums:
            canv.setFont('Helvetica', 10)
            canv.drawString(36, y, ' '.join(nums))
            y -= 14
    if actual:
        canv._code.append('EMC')
    canv.save()
    return buf.getvalue()


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
        deadline = time.time() + 180
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
        swapped = _true_framework_swap(para)
        _assert_true_framework_swap(self, para, swapped)
        blockers = _paragraph_pdf_blockers(
            0, para, swapped, visible=swapped, actual=swapped)
        self.assertTrue(blockers, blockers)
        self.assertFalse(any(
            item in blockers for item in (
                'pdf_bytes_missing', 'pdf_extraction_unreliable',
                'pdf_environment_painted_unestablished:0',
            )
        ), blockers)

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


class OfficialNumericOverlayAssociationTests(unittest.TestCase):
    """Identity digits must not authorize a changed quantitative value."""

    def _helper(self, expected, painted, actual):
        return _paragraph_pdf_blockers(
            0, expected, painted, visible=painted, actual=actual)

    def _content_blocker(self, blockers):
        self.assertTrue(blockers, blockers)
        forbidden = {
            'pdf_bytes_missing',
            'pdf_extraction_unreliable',
            'pdf_environment_section_unassociated',
        }
        self.assertFalse(any(
            item in forbidden or item.endswith('painted_unestablished:0')
            for item in blockers
        ), blockers)

    def test_helper_a_b_accept_c_through_h_refuse(self):
        wrap = _NUMERIC_PARA.replace('لمدة 10', 'لمدة\n10')
        self.assertEqual(self._helper(_NUMERIC_PARA, _NUMERIC_PARA, _NUMERIC_PARA), [])
        self.assertEqual(self._helper(_NUMERIC_PARA, wrap, _NUMERIC_PARA), [])
        self._content_blocker(self._helper(
            _NUMERIC_PARA, _NUMERIC_MUT_33, _NUMERIC_PARA))
        self._content_blocker(self._helper(
            _NUMERIC_PARA, _NUMERIC_RANGE_33, _NUMERIC_PARA))
        self._content_blocker(self._helper(
            _NUMERIC_PARA, _NUMERIC_RANGE_1_10, _NUMERIC_PARA))
        self._content_blocker(self._helper(
            _NUMERIC_PARA, _NUMERIC_RANGE_1_10, _NUMERIC_RANGE_1_10))
        self._content_blocker(self._helper(
            _NUMERIC_PARA, _NUMERIC_RANGE_8_10, _NUMERIC_PARA))
        self._content_blocker(self._helper(
            _NUMERIC_PARA_P8,
            _NUMERIC_PARA_P8.replace('10 سنوات', f'1{_EN_DASH}10 سنوات'),
            _NUMERIC_PARA_P8))
        self._content_blocker(self._helper(
            _NUMERIC_PARA, _NUMERIC_RANGE_33, _NUMERIC_RANGE_33))
        self._content_blocker(self._helper(
            _NUMERIC_PARA, _NUMERIC_RANGE_88, _NUMERIC_PARA))
        self._content_blocker(self._helper(
            _NUMERIC_PARA_REL88,
            _NUMERIC_PARA_REL88.replace('10 سنوات', f'10{_EN_DASH}33 سنوات'),
            _NUMERIC_PARA_REL88))
        self.assertEqual(_content_words(_NUMERIC_MUT_33).count('10.33'), 1)
        self.assertNotIn('33', _content_words(_NUMERIC_MUT_33))
        self.assertEqual(_content_words(_NUMERIC_RANGE_33).count('10'), 1)
        self.assertEqual(_content_words(_NUMERIC_RANGE_33).count('33'), 1)
        self.assertEqual(_content_words(_NUMERIC_RANGE_1_10).count('1'), 1)
        self.assertEqual(_content_words(_NUMERIC_RANGE_1_10).count('10'), 1)
        self.assertIn('33', _identity_digit_remnants(_NUMERIC_PARA))
        self.assertIn('1', _identity_digit_remnants(_NUMERIC_PARA))
        self.assertFalse(_is_identity_digit_remnant('10.33', _NUMERIC_PARA))
        self.assertTrue(_is_identity_digit_remnant('33', _NUMERIC_PARA))
        self.assertTrue(_is_identity_digit_remnant('1', _NUMERIC_PARA))
        self.assertTrue(_identifier_owns_digit_chip('P1', '1'))
        self.assertTrue(_identifier_owns_digit_chip('REL33', '33'))
        self.assertFalse(_identifier_owns_digit_chip('لمدة', '1'))
        self.assertFalse(_identifier_owns_digit_chip('10', '33'))
        matching_extra = _NUMERIC_PARA[::-1] + '\n' + _NUMERIC_PARA
        self.assertEqual(
            self._helper(_NUMERIC_PARA, matching_extra, _NUMERIC_PARA), [])
        self.assertTrue(_is_visual_leftover_run(_NUMERIC_PARA[::-1], _NUMERIC_PARA))
        wrong = _NUMERIC_PARA.replace('10 سنوات', '88 سنوات')
        contradictory_extra = wrong[::-1] + '\n' + _NUMERIC_PARA
        extra_run = wrong[::-1]
        self.assertFalse(_leftover_non_arabic_accounted(extra_run, _NUMERIC_PARA))
        self.assertFalse(_arabic_leftover_rotation_of_actual(
            extra_run, _NUMERIC_PARA))
        self.assertFalse(_is_visual_leftover_run(extra_run, _NUMERIC_PARA))
        self._content_blocker(self._helper(
            _NUMERIC_PARA, contradictory_extra, _NUMERIC_PARA))

    def test_actual_pdf_visible_10_versus_10_33(self):
        class _Model:
            environment_narrative = _NUMERIC_PARA
            lang = 'ar'
            domain = 'data'
            org_name = 'REL33 P1 Data Management Org'
            model_hash = 'test-owned-numeric'
            sector = 'Government'
            selected_frameworks = ['NDMO', 'PDPL']

        model = _Model()
        good = _numeric_env_pdf(_NUMERIC_PARA, _NUMERIC_PARA)
        self.assertTrue(good.startswith(b'%PDF'))
        section, meta = pdf_environment_section_text(good)
        self.assertTrue(meta.get('associated'), meta)
        vis = str(meta.get('environment_visible') or '')
        act = str(meta.get('environment_actual') or '')
        self.assertIn('10', vis)
        self.assertNotIn('10.33', vis)
        self.assertIn('10', act)
        self.assertNotIn('10.33', act)
        self.assertEqual(compare_environment_narrative_to_pdf(model, good), [])

        paint_only = _numeric_env_pdf(_NUMERIC_MUT_33, _NUMERIC_PARA)
        section, meta = pdf_environment_section_text(paint_only)
        vis = str(meta.get('environment_visible') or '')
        act = str(meta.get('environment_actual') or '')
        self.assertIn('10.33', vis)
        self.assertNotIn('10.33', act)
        self.assertIn('10', act)
        blockers = compare_environment_narrative_to_pdf(model, paint_only)
        self._content_blocker(blockers)

        both = _numeric_env_pdf(_NUMERIC_MUT_33, _NUMERIC_MUT_33)
        section, meta = pdf_environment_section_text(both)
        vis = str(meta.get('environment_visible') or '')
        act = str(meta.get('environment_actual') or '')
        self.assertIn('10.33', vis)
        self.assertIn('10.33', act)
        blockers = compare_environment_narrative_to_pdf(model, both)
        self._content_blocker(blockers)

        range_paint = _numeric_env_pdf(_NUMERIC_RANGE_33, _NUMERIC_PARA)
        section, meta = pdf_environment_section_text(range_paint)
        vis = str(meta.get('environment_visible') or '')
        act = str(meta.get('environment_actual') or '')
        self.assertTrue('10.33' not in vis and ('10–33' in vis or '10-33' in vis or '33' in vis), vis)
        self.assertNotIn(_EN_DASH.join(('10', '33')), act)
        self.assertIn('10', act)
        self._content_blocker(compare_environment_narrative_to_pdf(model, range_paint))
        range_both = _numeric_env_pdf(_NUMERIC_RANGE_33, _NUMERIC_RANGE_33)
        self._content_blocker(compare_environment_narrative_to_pdf(model, range_both))

        lower_paint = _numeric_env_pdf(_NUMERIC_RANGE_1_10, _NUMERIC_PARA)
        section, meta = pdf_environment_section_text(lower_paint)
        vis = str(meta.get('environment_visible') or '')
        act = str(meta.get('environment_actual') or '')
        self.assertTrue(meta.get('associated'), meta)
        self.assertTrue('1' in vis and '10' in vis, vis)
        self.assertNotIn(_EN_DASH.join(('1', '10')), act)
        self.assertIn('10', act)
        self._content_blocker(compare_environment_narrative_to_pdf(model, lower_paint))
        lower_both = _numeric_env_pdf(_NUMERIC_RANGE_1_10, _NUMERIC_RANGE_1_10)
        self._content_blocker(compare_environment_narrative_to_pdf(model, lower_both))
        del section

    def test_real_thread_rejects_foreign_numeric_pdf(self):
        """Official Data source vs a different numeric paragraph PDF.

        This is a mismatched-document refusal, not a same-source numeric
        mutation. Baseline already refused it; it is not a downloadable
        bad-file bypass that this change fixed.
        """
        from unittest.mock import patch

        domain, label, org, sector, fws = _CASES[0]
        model = _compile(domain, org, sector, fws)
        before = model.model_hash
        saved = _persist(model, domain_label=label)
        matching = _export(saved, _official_body(saved, fws=fws), 'pdf')
        self.assertEqual(matching['status'].get('status'), 'done', matching['status'])
        self.assertEqual(matching['download_http'], 200)
        self.assertTrue(matching['bytes'].startswith(b'%PDF'))
        self.assertEqual(
            compare_environment_narrative_to_pdf(model, matching['bytes']), [])
        self.assertEqual(model.model_hash, before)
        self.assertEqual(before, LIVE_HASHES['data'])

        real_gate = app_mod._rel37_gate_saved_export_bytes
        corrupt = _numeric_env_pdf(_NUMERIC_MUT_33, _NUMERIC_PARA)

        def injecting_gate(*, docx_bytes=None, pdf_bytes=None, sections=None,
                           route='pdf', lang='ar'):
            if pdf_bytes and pdf_bytes.startswith(b'%PDF'):
                pdf_bytes = corrupt
            return real_gate(
                docx_bytes=docx_bytes, pdf_bytes=pdf_bytes,
                sections=sections, route=route, lang=lang)

        with patch.object(app_mod, '_rel37_gate_saved_export_bytes', injecting_gate):
            refused = _export(saved, _official_body(saved, fws=fws), 'pdf')
        self.assertNotEqual(refused['status'].get('status'), 'done', refused['status'])
        self.assertNotEqual(refused['download_http'], 200)
        self.assertFalse(refused['bytes'].startswith(b'%PDF'))
        self.assertEqual(model.model_hash, before)

    def _owned_numeric_model(self):
        domain, label, org, sector, fws = _CASES[0]
        model = _compile(domain, org, sector, fws)
        official_hash = model.model_hash
        model.environment_narrative = (
            model.environment_narrative.rstrip() + '\n\n' + _NUMERIC_PARA)
        model.compute_hashes()
        self.assertNotEqual(model.model_hash, official_hash)
        self.assertNotEqual(model.model_hash, LIVE_HASHES['data'])
        self.assertIn(_NUMERIC_PARA, model.environment_narrative)
        return model, label, fws

    def _substitute_candidate(self, saved, fws, raw):
        """Replace builder output before the real REL37 gate and response.

        The previous wrapper only swapped the gate argument. The original
        renderer file was still written and downloaded. This substitute
        is the candidate the gate sees and the candidate returned.
        """
        import hashlib
        from io import BytesIO
        from unittest.mock import patch

        real_gate = app_mod._rel37_gate_saved_export_bytes
        seen = {'gate_input_sha': None, 'gate_blockers': None}

        def substituting_gate(*, docx_bytes=None, pdf_bytes=None, sections=None,
                              route='pdf', lang='ar'):
            if pdf_bytes and pdf_bytes.startswith(b'%PDF'):
                pdf_bytes = raw
            seen['gate_input_sha'] = hashlib.sha256(pdf_bytes or b'').hexdigest()
            allowed, blockers, detail = real_gate(
                docx_bytes=docx_bytes, pdf_bytes=pdf_bytes,
                sections=sections, route=route, lang=lang)
            seen['gate_blockers'] = list(blockers)
            return allowed, blockers, detail

        import flask
        real_send_file = flask.send_file

        def substituting_send_file(file_obj, **kwargs):
            mime = str(kwargs.get('mimetype') or '')
            if mime == 'application/pdf' or mime.endswith('pdf'):
                return real_send_file(BytesIO(raw), **kwargs)
            return real_send_file(file_obj, **kwargs)

        with patch.object(app_mod, '_rel37_gate_saved_export_bytes', substituting_gate):
            with patch.object(flask, 'send_file', substituting_send_file):
                result = _export(saved, _official_body(saved, fws=fws), 'pdf')
        result['candidate_sha'] = hashlib.sha256(raw).hexdigest()
        result['gate_input_sha'] = seen['gate_input_sha']
        result['downloaded_sha'] = hashlib.sha256(result['bytes'] or b'').hexdigest()
        result['gate_blockers'] = seen['gate_blockers']
        return result

    def test_real_thread_same_source_numeric_mutations(self):
        from release_engine_v3.rel37_export_content_parity import (
            gate_rel37_returned_bytes,
        )

        model, label, fws = self._owned_numeric_model()
        before = model.model_hash
        saved = _persist(model, domain_label=label)
        matching = _export(saved, _official_body(saved, fws=fws), 'pdf')
        self.assertEqual(matching['status'].get('status'), 'done', matching['status'])
        self.assertEqual(matching['download_http'], 200)
        self.assertTrue(matching['bytes'].startswith(b'%PDF'))
        blockers = compare_environment_narrative_to_pdf(model, matching['bytes'])
        self.assertEqual(blockers, [], blockers)
        self.assertEqual(model.model_hash, before)

        env = model.environment_narrative
        same_layout = _numeric_env_pdf(env, env)
        constructed = self._substitute_candidate(saved, fws, same_layout)
        self.assertEqual(
            constructed['status'].get('status'), 'done', constructed['status'])
        self.assertEqual(constructed['download_http'], 200)
        self.assertTrue(constructed['bytes'].startswith(b'%PDF'))
        self.assertEqual(constructed['candidate_sha'], constructed['gate_input_sha'])
        self.assertEqual(constructed['candidate_sha'], constructed['downloaded_sha'])
        self.assertEqual(
            compare_environment_narrative_to_pdf(model, constructed['bytes']), [])
        self.assertEqual(model.model_hash, before)

        paint_decimal = _numeric_env_pdf(
            env.replace('لمدة 10 سنوات', 'لمدة 10.33 سنوات'), env)
        paint_upper = _numeric_env_pdf(
            env.replace('لمدة 10 سنوات', f'لمدة 10{_EN_DASH}33 سنوات'), env)
        paint_lower = _numeric_env_pdf(
            env.replace('لمدة 10 سنوات', f'لمدة 1{_EN_DASH}10 سنوات'), env)
        both_lower = _numeric_env_pdf(
            env.replace('لمدة 10 سنوات', f'لمدة 1{_EN_DASH}10 سنوات'),
            env.replace('لمدة 10 سنوات', f'لمدة 1{_EN_DASH}10 سنوات'),
        )
        for name, raw in (
                ('paint_10_33', paint_decimal),
                ('paint_10_33_range', paint_upper),
                ('paint_1_10_range', paint_lower),
                ('both_1_10_range', both_lower),
        ):
            section, meta = pdf_environment_section_text(raw)
            self.assertTrue(meta.get('associated'), (name, meta))
            vis = str(meta.get('environment_visible') or '')
            act = str(meta.get('environment_actual') or '')
            if name == 'paint_10_33':
                self.assertIn('10.33', vis)
                self.assertNotIn('10.33', act)
            elif name == 'paint_10_33_range':
                self.assertTrue('33' in vis, (name, vis))
            else:
                self.assertTrue('1' in vis and '10' in vis, (name, vis))
            cmp_blockers = compare_environment_narrative_to_pdf(model, raw)
            self._content_blocker(cmp_blockers)
            numeric_idx = None
            for idx, para in enumerate(environment_narrative_paragraphs(env)):
                if _NUMERIC_PARA in para or para == _NUMERIC_PARA:
                    numeric_idx = idx
                    break
            self.assertIsNotNone(numeric_idx, env)
            self.assertTrue(any(
                item.endswith(f':{numeric_idx}')
                and (
                    'actual_visible_disagree' in item
                    or 'narrative_missing' in item
                    or 'narrative_incomplete' in item
                )
                for item in cmp_blockers
            ), (name, numeric_idx, cmp_blockers))
            allowed, gated = gate_rel37_returned_bytes(
                model, pdf_bytes=raw, route='pdf')
            self.assertFalse(allowed, (name, gated))
            self.assertFalse(any(
                item in gated for item in (
                    'pdf_bytes_missing', 'pdf_extraction_unreliable',
                    'docx_bytes_missing',
                )
            ), (name, gated))
            self.assertTrue(any(
                item.endswith(f':{numeric_idx}')
                and (
                    'actual_visible_disagree' in item
                    or 'narrative_missing' in item
                    or 'narrative_incomplete' in item
                )
                for item in gated
            ), (name, numeric_idx, gated))
            refused = self._substitute_candidate(saved, fws, raw)
            self.assertNotEqual(
                refused['status'].get('status'), 'done', (name, refused['status']))
            self.assertNotEqual(refused['download_http'], 200, name)
            self.assertFalse(refused['bytes'].startswith(b'%PDF'), name)
            self.assertEqual(refused['candidate_sha'], refused['gate_input_sha'], name)
            self.assertNotEqual(refused['candidate_sha'], refused['downloaded_sha'], name)
            route_blockers = refused.get('gate_blockers') or []
            self.assertTrue(any(
                item.endswith(f':{numeric_idx}')
                and (
                    'actual_visible_disagree' in item
                    or 'narrative_missing' in item
                    or 'narrative_incomplete' in item
                )
                for item in route_blockers
            ), (name, numeric_idx, route_blockers, refused['status']))
        self.assertEqual(model.model_hash, before)
        del section

    def test_leftover_identity_chips_still_associate(self):
        para = (
            'تعمل REL33 P1 Data Management Org في سياق تشغيلي لقطاع حكومي، '
            'ضمن بيئة تنظيمية تتطلب حوكمة بيانات وطنية وفق NDMO وحماية '
            'بيانات شخصية وفق PDPL، مع ضغط متزايد على جودة البيانات.')
        leftover = para + ' 33 1 REL33 P1 Data Management Org'
        self.assertEqual(
            self._helper(para, leftover, para), [])
        adjacent = para.replace('P1 Data', 'P1 1 Data')
        self.assertEqual(self._helper(para, adjacent, para), [])
        ai_para = (
            'تعمل REL33 P1 Artificial Intelligence Org في سياق تشغيلي '
            'لقطاع حكومي، ضمن بيئة تتطلب امتثال إطار SDAIA للذكاء '
            'الاصطناعي المسؤول، بما في ذلك سجل النماذج ومخاطر النموذج '
            'والإشراف البشري وجاهزية البيانات قبل الإطلاق.')
        mashed_prefix = (
            'لمعت 33 1 ب ،لوؤسملا يعانطصالا ءاكذلل راطإ لاثتما بلطتت '
            'ةئيب نمض ،يموكح عاطقل يليغشت قايس يف '
        ) + ai_para
        self.assertEqual(
            self._helper(ai_para, mashed_prefix, ai_para), [])
        unrelated_same_digit = para.replace(
            'حوكمة بيانات', 'حوكمة 1 بيانات')
        self._content_blocker(self._helper(
            para, unrelated_same_digit, para))

        class _Model:
            environment_narrative = para
            lang = 'ar'
            domain = 'data'
            org_name = 'REL33 P1 Data Management Org'
            model_hash = 'test-owned-leftover'
            sector = 'Government'
            selected_frameworks = ['NDMO', 'PDPL']

        model = _Model()
        leftover_pdf = _numeric_env_pdf(leftover, para)
        section, meta = pdf_environment_section_text(leftover_pdf)
        self.assertTrue(meta.get('associated'), meta)
        self.assertTrue(leftover_pdf.startswith(b'%PDF'))
        self.assertEqual(compare_environment_narrative_to_pdf(model, leftover_pdf), [])
        del section

    def test_contradictory_extra_paint_is_not_leftover_rotation(self):
        """Matching leftover extra stays valid; altered quantitative extra does not.

        The same-route constructed-positive control is a separate resolved
        test. This case keeps that boundary and only changes the extra run.
        """
        from release_engine_v3.rel37_export_content_parity import (
            extract_pdf_pages,
            gate_rel37_returned_bytes,
        )

        class _Model:
            environment_narrative = _NUMERIC_PARA
            lang = 'ar'
            domain = 'data'
            org_name = 'REL33 P1 Data Management Org'
            model_hash = 'test-owned-extra-run'
            sector = 'Government'
            selected_frameworks = ['NDMO', 'PDPL']

        model = _Model()
        matching_vis = _NUMERIC_PARA[::-1] + '\n' + _NUMERIC_PARA
        matching_pdf = _numeric_env_pdf(matching_vis, _NUMERIC_PARA)
        section, meta = pdf_environment_section_text(matching_pdf)
        self.assertTrue(meta.get('associated'), meta)
        self.assertEqual(
            compare_environment_narrative_to_pdf(model, matching_pdf), [])

        wrong = _NUMERIC_PARA.replace('10 سنوات', '88 سنوات')
        extra_vis = wrong + '\n' + _NUMERIC_PARA
        extra_pdf = _numeric_env_pdf(extra_vis, _NUMERIC_PARA)
        section, meta = pdf_environment_section_text(extra_pdf)
        vis = str(meta.get('environment_visible') or '')
        act = str(meta.get('environment_actual') or '')
        self.assertTrue(meta.get('associated'), meta)
        self.assertIn('88', vis)
        self.assertNotIn('88', act)
        self.assertIn('10', act)
        pages, page_meta = extract_pdf_pages(extra_pdf)
        painted_88 = False
        hidden_88 = False
        for page in pages:
            for event in page.get('events') or []:
                text = str(event.get('text') or '')
                if '88' not in text:
                    continue
                if event.get('kind') == 'visible' and not event.get('non_displayed'):
                    painted_88 = True
                if event.get('kind') == 'hidden_logical' or event.get('non_displayed'):
                    hidden_88 = True
        self.assertTrue(painted_88, (vis, page_meta, pages))
        self.assertFalse(hidden_88)
        blockers = compare_environment_narrative_to_pdf(model, extra_pdf)
        self._content_blocker(blockers)
        del section

        owned, label, fws = self._owned_numeric_model()
        before = owned.model_hash
        saved = _persist(owned, domain_label=label)
        env = owned.environment_narrative
        route_match = _numeric_env_pdf(
            _NUMERIC_PARA[::-1] + '\n' + env, env)
        constructed = self._substitute_candidate(saved, fws, route_match)
        self.assertEqual(
            constructed['status'].get('status'), 'done', constructed['status'])
        self.assertEqual(constructed['download_http'], 200)
        self.assertEqual(constructed['candidate_sha'], constructed['gate_input_sha'])
        self.assertEqual(constructed['candidate_sha'], constructed['downloaded_sha'])
        self.assertEqual(
            compare_environment_narrative_to_pdf(owned, constructed['bytes']), [])

        route_wrong = _numeric_env_pdf(wrong + '\n' + env, env)
        allowed, gated = gate_rel37_returned_bytes(
            owned, pdf_bytes=route_wrong, route='pdf')
        self.assertFalse(allowed, gated)
        self.assertTrue(any(
            'actual_visible_disagree' in item
            or 'narrative_missing' in item
            or 'narrative_incomplete' in item
            for item in gated
        ), gated)
        refused = self._substitute_candidate(saved, fws, route_wrong)
        self.assertNotEqual(
            refused['status'].get('status'), 'done', refused['status'])
        self.assertNotEqual(refused['download_http'], 200)
        self.assertFalse(refused['bytes'].startswith(b'%PDF'))
        self.assertEqual(refused['candidate_sha'], refused['gate_input_sha'])
        self.assertNotEqual(refused['candidate_sha'], refused['downloaded_sha'])
        self.assertTrue(any(
            'actual_visible_disagree' in item
            or 'narrative_missing' in item
            or 'narrative_incomplete' in item
            for item in (refused.get('gate_blockers') or [])
        ), refused.get('gate_blockers'))
        self.assertEqual(owned.model_hash, before)

