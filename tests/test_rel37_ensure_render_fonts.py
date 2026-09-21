"""Checksum and fallback contract for supported Arabic PDF font acquisition."""
from __future__ import annotations

import hashlib
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'ensure_render_fonts.py'
APP = ROOT / 'app.py'


def _load_ensure():
    spec = importlib.util.spec_from_file_location('ensure_render_fonts', SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class EnsureRenderFontsTests(unittest.TestCase):
    def test_pinned_identity_and_min_size(self):
        mod = _load_ensure()
        self.assertEqual(
            mod.AMIRI_SHA256,
            'ab391c4147d054c48976e98322ad0eefe1427aa0e0502a12a4c75d80a70cfcd7',
        )
        self.assertEqual(
            mod.NOTO_SHA256,
            'ceea25b464a656dc3b26849bab9356740401af62aedf1bfa8b7f0d9b75925b1b',
        )
        self.assertIn(mod.AMIRI_COMMIT, mod.URL)
        self.assertGreaterEqual(mod.AMIRI_MIN_BYTES, 400000)
        names = [item['name'] for item in mod.FONTS]
        self.assertEqual(
            names,
            ['NotoSansArabic-Regular.ttf', 'Amiri-Regular.ttf'],
        )
        self.assertTrue(mod.URL.startswith('https://raw.githubusercontent.com/google/fonts/'))

    def test_verify_rejects_checksum_mismatch_and_short_file(self):
        mod = _load_ensure()
        with tempfile.TemporaryDirectory() as tmp:
            short = os.path.join(tmp, 'short.ttf')
            with open(short, 'wb') as handle:
                handle.write(b'short')
            with self.assertRaises(RuntimeError) as short_err:
                mod.verify_font(short)
            self.assertIn('too small', str(short_err.exception))

            fake = os.path.join(tmp, 'fake.ttf')
            payload = b'A' * (mod.AMIRI_MIN_BYTES + 10)
            with open(fake, 'wb') as handle:
                handle.write(payload)
            digest = hashlib.sha256(payload).hexdigest()
            self.assertNotEqual(digest, mod.AMIRI_SHA256)
            with self.assertRaises(RuntimeError) as mismatch:
                mod.verify_font(fake)
            self.assertIn('checksum mismatch', str(mismatch.exception))

    def test_dejavu_last_resort_not_removed_from_search(self):
        text = APP.read_text(encoding='utf-8')
        self.assertIn('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', text)
        self.assertIn('static/fonts/Amiri-Regular.ttf', text)
        bundled_noto = text.find("'static/fonts/NotoSansArabic-Regular.ttf'")
        bundled_amiri = text.find("'static/fonts/Amiri-Regular.ttf'")
        self.assertGreater(bundled_noto, 0)
        self.assertGreater(bundled_amiri, 0)
        self.assertLess(
            text.find('NotoSansArabic-Regular.ttf'),
            bundled_amiri,
        )
        self.assertLess(bundled_noto, bundled_amiri)
        self.assertLess(
            bundled_amiri,
            text.find('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'),
        )
        self.assertIn('last-resort fallback: DejaVu', text)
        self.assertIn('not an evidence exemption', text)

    def test_export_diagnostic_strips_secrets_and_names_blocker(self):
        from tests._export_failure_diagnostics import (
            blocking_errors_from_text,
            build_export_diagnostic,
            sanitize,
        )
        dirty = {
            'task_id': 'd86cc60f-3543-499c-ac01-c1715fcb201e',
            'password': 'secret-password',
            'csrf_token': 'csrf-value',
            'Authorization': 'Bearer abc',
            'cookie': 'session=1',
        }
        clean = sanitize(dirty)
        self.assertEqual(clean['task_id'], dirty['task_id'])
        self.assertNotIn('password', clean)
        self.assertNotIn('csrf_token', clean)
        self.assertNotIn('Authorization', clean)
        self.assertNotIn('cookie', clean)
        stdout = (
            "[REL37-RETURNED-BYTES-GATE] PDF blocked "
            "errors=['pdf_environment_actual_visible_disagree:1'] "
            "gate={'model_hash': '97a4831f'}"
        )
        self.assertEqual(
            blocking_errors_from_text(stdout),
            ['pdf_environment_actual_visible_disagree:1'],
        )
        payload = build_export_diagnostic(
            submit_http=200,
            submit=dirty,
            status={
                'status': 'error',
                'error': 'Export blocked — actual PDF evidence validation failed',
                'csrf_token': 'hidden',
            },
            raw=b'',
            stdout_text=stdout,
            model_hash='97a4831fe99430c4bba90e7c4c38064aee20b559af7363298f3ad496000df5b3',
            font_path='/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
            fmt='pdf',
        )
        self.assertEqual(payload['raw_len'], 0)
        self.assertEqual(
            payload['blocking_errors'],
            ['pdf_environment_actual_visible_disagree:1'],
        )
        self.assertNotIn('csrf_token', payload['status'])
        self.assertNotIn('password', payload['submit'])
        self.assertTrue(payload['error'])


if __name__ == '__main__':
    unittest.main()
