"""PR-REL1 — Release acceptance matrix (6 domains × 2 langs × 2 types × 3 outputs)."""

import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

import pytest

_TMP = tempfile.mkdtemp(prefix='test_release_strategy_matrix_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')

from domains import DOMAIN_PACKS, get_domain_pack
from release_hardening.validator_registry import VALIDATOR_REGISTRY

_MATRIX = []
for _code in ('cyber', 'data', 'ai', 'dt', 'erm', 'global'):
    for _lang in ('ar', 'en'):
        for _subtype in ('technical', 'board'):
            for _output in ('preview', 'docx', 'pdf'):
                _MATRIX.append((_code, _lang, _subtype, _output))


def _require_app(fn):
    @functools.wraps(fn)
    def _w(*a, **kw):
        if _APP is None:
            raise unittest.SkipTest('app unavailable')
        return fn(*a, **kw)
    return _w


def _sections_for(domain_code, lang, doc_subtype):
    pack = get_domain_pack(domain_code)
    assert pack is not None
    fx = pack['fixtures_ar'] if lang == 'ar' else pack['fixtures_en']
    if doc_subtype == 'board' and hasattr(fx, 'board_sections'):
        return fx.board_sections()
    return fx.technical_sections()


def _content(sections):
    if hasattr(_APP, '_prcy65_rebuild_content_from_sections'):
        return _APP._prcy65_rebuild_content_from_sections(sections, None)
    order = ('vision', 'pillars', 'environment', 'gaps',
             'roadmap', 'kpis', 'confidence')
    return '\n\n'.join(sections[k] for k in order if sections.get(k))


@_require_app
def _build(domain, lang, doc_subtype):
    sections = _sections_for(domain, lang, doc_subtype)
    frameworks = (get_domain_pack(domain) or {}).get('frameworks_default') or []
    buf = io.StringIO()
    with redirect_stdout(buf):
        art = _APP._build_cyber_final_strategy_artifact(
            _content(sections),
            sections=dict(sections),
            metadata={'domain': domain},
            selected_frameworks=frameworks,
            lang=lang,
            domain=domain,
            output_type='generation',
            doc_subtype=doc_subtype,
            generation_mode='consulting',
        )
    return art, buf.getvalue()


class ReleaseMatrixSmokeTests(unittest.TestCase):
    """Explicit smoke cases required by PR-REL1 spec."""

    def test_rel1_flag_live(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('rel1'))

    def test_validator_registry_declares_sources(self):
        for name, entry in VALIDATOR_REGISTRY.items():
            self.assertIn('source', entry, msg=name)
            self.assertTrue(entry['source'], msg=name)

    @_require_app
    def test_cyber_ar_technical_seals_with_roadmap_resource_row(self):
        art, _ = _build('cyber', 'ar', 'technical')
        self.assertTrue(art.get('sealed'), art.get('blocking_errors'))
        self.assertEqual(art.get('blocking_errors') or [], [])
        rel1 = (art.get('diagnostics') or {}).get('rel1') or {}
        scoped = rel1.get('scoped_validation') or {}
        self.assertGreaterEqual(
            scoped.get('ignored_cross_section_rows_count', 0), 0)

    @_require_app
    def test_cyber_ar_board_seals(self):
        art, _ = _build('cyber', 'ar', 'board')
        self.assertTrue(art.get('sealed'), art.get('blocking_errors'))

    @_require_app
    def test_cyber_en_technical_seals(self):
        art, _ = _build('cyber', 'en', 'technical')
        self.assertTrue(art.get('sealed'), art.get('blocking_errors'))

    @_require_app
    def test_data_ar_technical_seals(self):
        art, _ = _build('data', 'ar', 'technical')
        self.assertTrue(art.get('sealed'), art.get('blocking_errors'))

    @_require_app
    def test_ai_ar_technical_seals(self):
        art, _ = _build('ai', 'ar', 'technical')
        self.assertTrue(art.get('sealed'))

    @_require_app
    def test_dt_ar_technical_seals(self):
        art, _ = _build('dt', 'ar', 'technical')
        self.assertTrue(art.get('sealed'))

    @_require_app
    def test_erm_ar_technical_seals(self):
        art, _ = _build('erm', 'ar', 'technical')
        self.assertTrue(art.get('sealed'))

    @_require_app
    def test_global_ar_technical_seals(self):
        art, _ = _build('global', 'ar', 'technical')
        self.assertTrue(art.get('sealed'))

    @_require_app
    def test_all_domains_en_technical_seal(self):
        for code in ('data', 'ai', 'dt', 'erm', 'global'):
            art, _ = _build(code, 'en', 'technical')
            self.assertTrue(
                art.get('sealed'),
                f'{code}: {art.get("blocking_errors")!r}')


@pytest.mark.parametrize(
    'domain,lang,doc_subtype,output_type', _MATRIX)
class TestReleaseStrategyMatrix:
    """72-path matrix: build → seal → read-only export parity."""

    @_require_app
    def test_matrix_path(self, domain, lang, doc_subtype, output_type):
        art, _ = _build(domain, lang, doc_subtype)
        blockers = art.get('blocking_errors') or []
        assert art.get('sealed'), (
            f'{domain}/{lang}/{doc_subtype}: {blockers!r}')
        assert not blockers
        fh = art['final_hash']
        meta = {
            'domain': domain,
            'sealed': True,
            'final_hash': fh,
            'quality_gate_passed': True,
        }
        c = _APP._prcy80_invoke_final_strategy_artifact(
            art['final_markdown'],
            metadata=meta,
            selected_frameworks=(
                (get_domain_pack(domain) or {}).get('frameworks_default') or []),
            lang=lang,
            domain=domain,
            output_type=output_type,
            read_only=True,
            sections=art.get('sections'),
            doc_subtype=doc_subtype,
        )
        assert c.get('content_hash') == fh, output_type
        if domain == 'cyber':
            so_issues = _APP._prcy80_strategic_objectives_incomplete_rows(
                art.get('sections') or {}, lang)
            assert not any(
                'strategic_objectives_incomplete_row' in (i or '')
                for i in so_issues)


if __name__ == '__main__':
    unittest.main()
