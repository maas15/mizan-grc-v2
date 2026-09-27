"""Test-side observation of an already-started async export task.

This does not change production worker timeouts. A nonterminal status at
the deadline is an observation timeout, not a terminal refusal and not
an HTTP denial.
"""
from __future__ import annotations

import os
import sys
import time
from typing import Any, Callable, Dict, Optional


def observe_export_task(
        get_status: Callable[[], Dict[str, Any]],
        *,
        task_id: Optional[str],
        deadline_s: float,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        poll_interval_s: float = 0.2,
) -> Dict[str, Any]:
    """Poll until done, error, not_found, or the monotonic deadline.

    ``done`` and ``error`` are terminal. ``not_found`` is a lost task,
    not a terminal export and not a pending timeout. ``download_requested``
    stays false. Callers issue GET only after a terminal status they
    choose to verify. ``download_http`` is not set here.
    """
    start = monotonic()
    deadline = start + float(deadline_s)
    last_status: Dict[str, Any] = {}
    observed_terminal = False
    lost_not_found = False
    if task_id:
        while True:
            last_status = get_status() or {}
            status_name = last_status.get('status')
            if status_name in ('done', 'error'):
                observed_terminal = True
                break
            if status_name == 'not_found':
                lost_not_found = True
                break
            if monotonic() >= deadline or poll_interval_s <= 0:
                break
            remaining = deadline - monotonic()
            if remaining <= 0:
                break
            sleep(min(poll_interval_s, remaining))
    elapsed = monotonic() - start
    return {
        'task_id': task_id,
        'last_status': last_status,
        'observed_terminal': observed_terminal,
        'lost_not_found': lost_not_found,
        'poll_timed_out': (
            bool(task_id) and not observed_terminal and not lost_not_found
        ),
        'elapsed_s': elapsed,
        'deadline_s': float(deadline_s),
        'download_requested': False,
    }


def stop_if_worker_still_uncontrolled(observed: Dict[str, Any]) -> None:
    """End this isolated test process if the worker is still nonterminal.

    Production threads are not cancelled. The process exit is the bound
    that keeps the next test from starting on a live worker.
    """
    if not observed.get('poll_timed_out'):
        return
    sys.stderr.write(
        'UNCONTROLLED_WORKER task_id=%s last_status=%s elapsed_s=%s\n'
        % (
            observed.get('task_id'),
            (observed.get('last_status') or {}).get('status'),
            observed.get('elapsed_s'),
        )
    )
    os._exit(3)
