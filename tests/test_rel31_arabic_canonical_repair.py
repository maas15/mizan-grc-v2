"""PR-REL3.1 — Arabic canonical repair before REL3 freeze."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel31_arabic_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_APP = None
try:
    _spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    sys.modules['app'] = _APP
except Exception as _e:
    raise SystemExit(f'Cannot load app: {_e!r}')

from release_engine.arabic_language_gate import (
    repair_arabic_canonical_text_before_freeze,
    repair_rel3_arabic_canonical_text,
)
from release_engine.rel31_acceptance_checks import repair_rel31_canonical_sections
from release_engine.rel31_content_substance_checks import evaluate_content_substance
from release_engine_v3.document_quality_spec import (
    check_arabic_tokenization_quality,
    evaluate_document_quality,
)
from release_engine_v3.evidence.docx_text_extractor import extract_docx_visible_text
from release_engine_v3.evidence.pdf_text_extractor import extract_pdf_visible_text
from release_engine_v3.orchestrator import clear_rel3_caches
from release_engine_v3.rel31_authority import (
    clear_rel3_route_artifact_hashes,
    emit_rel3_route_artifact_equivalence,
    record_rel3_route_artifact_hashes,
    rel3_export_authoritative,
)
from tests.fixtures.rel31_content_quality.latest_live_fixtures import (
    DOCX_LATEST,
    ensure_latest_live_fixtures,
    sections_from_latest_docx_text,
)


def _sections_with_residue(residue: str, *, section: str = 'vision') -> dict:
    return {
        section: (
            '## الرؤية\n\n'
            f'حماية أصول {residue} والبنية التحتية الحيوية للمنظمة.\n'
        ),
    }


def _export_all_routes(sections: dict, *, strategy_id: str = 'rel31-arabic-test'):
    clear_rel3_caches()
    clear_rel3_route_artifact_hashes()
    backend = _APP._rel31_backend_callables()
    md = _APP._prcy65_rebuild_content_from_sections(sections, None)
    art = {
        'sections': sections,
        'final_markdown': md,
        'domain': 'cyber',
        'sealed': True,
        'strategy_id': strategy_id,
        'contract_meta': {'lang': 'ar'},
    }
    backend['split_sections'] = lambda _c: dict(sections)
    kwargs = {
        'filename': 't.docx', 'lang': 'ar', 'domain': 'cyber',
        'selected_frameworks': ['NCA ECC', 'NCA DCC'],
    }
    preview = rel3_export_authoritative(
        'preview', art, backend=backend,
        flags={'rel3': True, 'rel31': True}, export_kwargs=kwargs)
    docx = rel3_export_authoritative(
        'docx', art, backend=backend,
        flags={'rel3': True, 'rel31': True}, export_kwargs=kwargs)
    pdf = rel3_export_authoritative(
        'pdf', art, backend=backend,
        flags={'rel3': True, 'rel31': True}, export_kwargs=kwargs)
    record_rel3_route_artifact_hashes(
        strategy_id, 'generation',
        canonical_hash=preview[0].canonical_hash,
        render_tree_hash=preview[0].render_tree_hash,
    )
    return preview, docx, pdf


class ArabicCanonicalDetectTests(unittest.TestCase):

    def test_01_al_malumat_fails_before_repair(self):
        bad = _sections_with_residue('ال معلومات')
        tok = check_arabic_tokenization_quality(bad['vision'])
        self.assertFalse(tok.get('passed'))
        self.assertIn('ال معلومات', tok.get('blocking_defects') or [])

    def test_02_al_malumat_becomes_almalumat_before_freeze(self):
        bad = _sections_with_residue('ال معلومات')
        repaired, diag = repair_arabic_canonical_text_before_freeze(bad, lang='ar')
        self.assertIn('المعلومات', repaired['vision'])
        self.assertNotIn('ال معلومات', repaired['vision'])
        self.assertTrue(diag.get('arabic_canonical_repair_passed'))
        self.assertEqual(diag.get('residues_after'), [])

    def test_03_dqs_fails_before_repair_passes_after(self):
        bad = _sections_with_residue('ال معلومات')
        tok_before = check_arabic_tokenization_quality(bad['vision'])
        self.assertFalse(tok_before.get('passed'))
        dq_before = evaluate_document_quality(
            canonical_artifact={'sections': bad, 'domain': 'cyber'},
            legacy_sections=bad,
            extracted_preview_text=bad['vision'],
            extracted_docx_text=bad['vision'],
            extracted_pdf_text='',
            pdf_bytes=b'',
        )
        self.assertIn(
            'arabic_canonical_invalid',
            ' '.join(dq_before.get('blocking_errors') or []))
        repaired, _ = repair_arabic_canonical_text_before_freeze(bad, lang='ar')
        tok_after = check_arabic_tokenization_quality(repaired['vision'])
        self.assertTrue(tok_after.get('passed'), tok_after.get('blocking_defects'))
        dq_after = evaluate_document_quality(
            canonical_artifact={'sections': repaired, 'domain': 'cyber'},
            legacy_sections=repaired,
            extracted_preview_text=repaired['vision'],
            extracted_docx_text=repaired['vision'],
            extracted_pdf_text='',
            pdf_bytes=b'',
        )
        joined = ' '.join(dq_after.get('blocking_errors') or [])
        self.assertNotIn('arabic_canonical_invalid', joined)

    def test_04_valid_arabic_not_corrupted(self):
        good = {
            'vision': 'حماية أصول المعلومات والمراقبة المستمرة للبنية التحتية.',
        }
        repaired, diag = repair_arabic_canonical_text_before_freeze(good, lang='ar')
        self.assertEqual(repaired['vision'], good['vision'])
        self.assertTrue(diag.get('arabic_canonical_repair_passed'))
        self.assertEqual(diag.get('residues_after'), [])

    def test_05_existing_residues_repaired(self):
        cases = (
            ('ال منظمة', 'المنظمة'),
            ('ال منتظم', 'المنتظم'),
            ('ل منصب', 'لمنصب'),
            ('ال معنية', 'المعنية'),
            ('معدلمعالجة', 'معدل معالجة'),
            ('الناجمةعن', 'الناجمة عن'),
            ('النقرفي', 'النقر في'),
        )
        for bad, good in cases:
            with self.subTest(bad=bad):
                out = repair_rel3_arabic_canonical_text(f'نص {bad} نص')
                self.assertIn(good, out)
                self.assertNotIn(bad, out)

    def test_06_emits_rel3_arabic_canonical_repair_diagnostic(self):
        bad = _sections_with_residue('ال معلومات')
        buf = StringIO()
        with redirect_stdout(buf):
            repair_arabic_canonical_text_before_freeze(bad, lang='ar')
        self.assertIn('[REL3-ARABIC-CANONICAL-REPAIR]', buf.getvalue())
        m = re.search(
            r'\[REL3-ARABIC-CANONICAL-REPAIR\] (\{.*\})', buf.getvalue())
        self.assertIsNotNone(m)
        payload = json.loads(m.group(1))
        self.assertIn('residues_before', payload)
        self.assertIn('residues_after', payload)
        self.assertEqual(payload.get('residues_after'), [])
        self.assertTrue(payload.get('arabic_canonical_repair_passed'))

    def test_08_empty_route_hashes_cannot_pass_equivalence(self):
        clear_rel3_route_artifact_hashes()
        buf = StringIO()
        with redirect_stdout(buf):
            diag = emit_rel3_route_artifact_equivalence('rel31-empty-routes')
        self.assertFalse(diag.get('route_artifact_equivalence_passed'))
        self.assertFalse(diag.get('all_route_hashes_equal'))
        self.assertIn(
            'rel3_route_equivalence_not_evaluated:no_route_hashes',
            diag.get('blocking_errors') or [])


class ArabicCanonicalLiveFixtureTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ensure_latest_live_fixtures()
        cls.docx_text = extract_docx_visible_text(DOCX_LATEST.read_bytes())
        cls.sections = sections_from_latest_docx_text(cls.docx_text)

    def test_07_live_fixture_al_malumat_passes_after_repair(self):
        bad = dict(self.sections)
        bad['vision'] = (
            (bad.get('vision') or '')
            + '\n\nحماية أصول ال معلومات الحيوية للمنظمة.\n'
        )
        tok_before = check_arabic_tokenization_quality(
            '\n'.join(str(v) for v in bad.values() if isinstance(v, str)))
        self.assertFalse(tok_before.get('passed'))
        backend = _APP._rel31_backend_callables()
        repaired, repairs = repair_rel31_canonical_sections(
            bad, lang='ar', domain='cyber', backend=backend)
        self.assertTrue(repairs)
        blob = '\n'.join(
            str(v) for k, v in repaired.items()
            if isinstance(v, str) and not str(k).startswith('_'))
        self.assertNotIn('ال معلومات', blob)
        tok_after = check_arabic_tokenization_quality(blob)
        self.assertTrue(tok_after.get('passed'), tok_after.get('blocking_defects'))

    def test_09_dqs_passes_preview_docx_pdf_after_repair(self):
        bad = dict(self.sections)
        bad['pillars'] = (
            (bad.get('pillars') or '')
            + '\n\nإدارة ال معلومات والبيانات الحساسة.\n'
        )
        backend = _APP._rel31_backend_callables()
        repaired, _ = repair_rel31_canonical_sections(
            bad, lang='ar', domain='cyber', backend=backend)
        preview, docx, pdf = _export_all_routes(
            repaired, strategy_id='rel31-arabic-dqs')
        docx_text = ''
        if docx[0].docx_bytes:
            docx_text = extract_docx_visible_text(docx[0].docx_bytes)
        pdf_text = extract_pdf_visible_text(pdf[0].pdf_bytes or b'')
        dq = evaluate_document_quality(
            canonical_artifact={'sections': repaired, 'domain': 'cyber'},
            legacy_sections=repaired,
            extracted_preview_text=preview[0].preview_text or '',
            extracted_docx_text=docx_text,
            extracted_pdf_text=pdf_text,
            pdf_bytes=pdf[0].pdf_bytes or b'',
        )
        self.assertTrue(dq.get('passed'), dq.get('blocking_errors'))
        joined = ' '.join(dq.get('blocking_errors') or [])
        self.assertNotIn('arabic_canonical_invalid', joined)

    def test_10_rel3_returned_file_evidence_after_arabic_repair(self):
        bad = dict(self.sections)
        bad['vision'] = (
            (bad.get('vision') or '')
            + '\n\nحماية ال معلومات والبيانات.\n'
        )
        backend = _APP._rel31_backend_callables()
        repaired, _ = repair_rel31_canonical_sections(
            bad, lang='ar', domain='cyber', backend=backend)
        _, docx_ev = _export_all_routes(repaired, strategy_id='rel31-arabic-ev')[1]
        self.assertTrue(docx_ev.export_return_allowed, docx_ev.blocking_errors)
        joined = ' '.join(docx_ev.blocking_errors or [])
        self.assertNotIn('ال معلومات', joined)
        self.assertNotIn('arabic_canonical_invalid', joined)

    def test_substance_arabic_residues_empty_after_repair(self):
        bad = dict(self.sections)
        bad['vision'] = (bad.get('vision') or '') + '\n\nال معلومات الحيوية.\n'
        backend = _APP._rel31_backend_callables()
        repaired, _ = repair_rel31_canonical_sections(
            bad, lang='ar', domain='cyber', backend=backend)
        blob = '\n'.join(
            str(v) for k, v in repaired.items()
            if isinstance(v, str) and not str(k).startswith('_'))
        diag = evaluate_content_substance(blob, route='docx')
        self.assertEqual(diag.get('arabic_residues'), [])


if __name__ == '__main__':
    unittest.main()
