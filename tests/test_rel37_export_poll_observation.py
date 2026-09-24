"""Polling-helper contract. These do not replace a real worker."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rel37_export_observation import observe_export_task


class _Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class ExportObservationTests(unittest.TestCase):
    def test_done_before_deadline(self):
        clock = _Clock()
        calls = {'n': 0}

        def get_status():
            calls['n'] += 1
            if calls['n'] >= 2:
                return {'status': 'done'}
            return {'status': 'pending'}

        obs = observe_export_task(
            get_status, task_id='task-done', deadline_s=10,
            monotonic=clock.monotonic, sleep=clock.sleep, poll_interval_s=1)
        self.assertTrue(obs['observed_terminal'])
        self.assertFalse(obs['poll_timed_out'])
        self.assertEqual(obs['last_status'].get('status'), 'done')
        self.assertFalse(obs['download_requested'])
        self.assertLess(obs['elapsed_s'], 10)

    def test_expected_error_before_deadline(self):
        clock = _Clock()

        def get_status():
            return {'status': 'error', 'error': 'pdf_environment_actual_visible_disagree:0'}

        obs = observe_export_task(
            get_status, task_id='task-error', deadline_s=10,
            monotonic=clock.monotonic, sleep=clock.sleep, poll_interval_s=1)
        self.assertTrue(obs['observed_terminal'])
        self.assertFalse(obs['poll_timed_out'])
        self.assertEqual(obs['last_status'].get('status'), 'error')
        self.assertFalse(obs['download_requested'])

    def test_pending_through_deadline(self):
        clock = _Clock()

        def get_status():
            return {'status': 'pending'}

        obs = observe_export_task(
            get_status, task_id='task-pending', deadline_s=3,
            monotonic=clock.monotonic, sleep=clock.sleep, poll_interval_s=1)
        self.assertFalse(obs['observed_terminal'])
        self.assertTrue(obs['poll_timed_out'])
        self.assertEqual(obs['last_status'].get('status'), 'pending')
        self.assertFalse(obs['download_requested'])
        self.assertGreaterEqual(obs['elapsed_s'], 3)
        self.assertEqual(obs['task_id'], 'task-pending')


if __name__ == '__main__':
    unittest.main()
