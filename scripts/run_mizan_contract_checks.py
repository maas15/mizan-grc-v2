"""Run only the correction regressions or the eight frozen Contract R nodes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "mizan_contract_r"
INPUTS = {
    "MIZAN_DOCX_POSITIVE_FIXTURE": ("MIZAN_CONTRACT_R_POSITIVE_STRATEGY_02.md", "b7a333a41a7cebf4e9747cafb74d9ae1b31d17d4c3df8255e5a130acf03f3495"),
    "MIZAN_DOCX_POSITIVE_EXPECTED": ("MIZAN_CONTRACT_R_POSITIVE_EXPECTED_CONTENT_02.json", "d83a727971abd8f5af4f0250a5ca79a689876584d030312cd88bfcc57e99c240"),
    "MIZAN_DOCX_REFUSAL_FIXTURE": ("REAL_DOCX_STRATEGY_FIXTURE.md", "03fef15d3982faf6751da59958fe2f3e2254889dd6164e6e55eba8e3189dc96e"),
    "MIZAN_DOCX_REFUSAL_EXPECTED": ("REAL_DOCX_EXPECTED_CONTENT.json", "446b5d44a8fa04aa643068de4184b470a1194b51b20037439744f0a2be571410"),
    "MIZAN_CONTRACT_R_F003_RAW_REFERENCE_PATH": ("extraction_sync_owner_response.json", "8bf9c039011b507ac3c5aedf2b7b63f55ec42b1251a3f09d15e090a911629e5e"),
}
REGRESSIONS = [
    "tests/test_shared_export_tasks.py::test_export_between_processes",
    "tests/test_shared_export_tasks.py::test_nonterminal_download_and_storage_failures",
    "tests/test_saved_dt_dispatch_and_reuse.py::test_gap_native_routes",
    "tests/test_saved_dt_dispatch_and_reuse.py::test_stored_strategy_binding_and_owner",
    "tests/test_saved_dt_dispatch_and_reuse.py::test_reordered_fresh_then_reuse",
]
CONTRACT = [
    f"tests/test_docx_contract_r_positive_02.py::test_contract_r_{record}_{path}{suffix}"
    for record, suffix in [(702, ""), (701, "_refusal")]
    for path in ("sync_fresh", "sync_matching_reuse", "async_fresh", "async_matching_reuse")
]


def run(lane):
    base = Path(tempfile.mkdtemp(prefix="mizan-contract-", dir=os.environ.get("RUNNER_TEMP")))
    print(f"Run evidence: {base}", flush=True)
    env = os.environ.copy()
    for key in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH", "DATABASE_URL"):
        env.pop(key, None)
    for key, (name, digest) in INPUTS.items():
        path = FIXTURES / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"Fixture identity mismatch: {name}")
        env[key] = str(path)
    env.update(SECRET_KEY="synthetic-contract-r-ci", ADMIN_PASSWORD="synthetic-admin-ci",
               PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONDONTWRITEBYTECODE="1",
               PYTHONUTF8="1", PYTHON_DOTENV_DISABLED="1")
    for node in REGRESSIONS if lane == "regressions" else CONTRACT:
        folder = base / node.split("::")[-1]
        folder.mkdir()
        temp = folder / "tmp"
        temp.mkdir()
        db = str(folder / "app.db")
        cfg = dict(env, DATABASE_PATH=db, MIZAN_DOCX_DATABASE_PATH=db,
                   TMP=str(temp), TEMP=str(temp), TMPDIR=str(temp))
        cmd = [sys.executable, "-B", "-m", "pytest", "-p", "no:cacheprovider",
               node, "--junitxml=" + str(folder / "junit.xml")]
        print(json.dumps(cmd), flush=True)
        subprocess.run(cmd, cwd=ROOT, env=cfg, check=True, timeout=300)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lane", choices=["regressions", "contract"])
    run(parser.parse_args().lane)
