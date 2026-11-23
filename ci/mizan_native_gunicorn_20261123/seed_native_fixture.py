#!/usr/bin/env python3
"""Seed exact fixture 702 into a disposable DB initialized by the real app.

The caller must first observe both Gunicorn post_worker_init events. This
utility only reads source data and writes SQLite/JSON; it never imports app,
pytest, a project helper, or a renderer. Credentials go to a separate private
file outside the public evidence directory. No existing fixture rows are
updated or deleted. Run once per fresh disposable database.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess


EXPECTED_HEAD = "3b713191631cb67580424bdf2d9461827f05ec02"
FIXTURES = {
    "body": (
        "MIZAN_CONTRACT_R_POSITIVE_STRATEGY_02.md",
        "b7a333a41a7cebf4e9747cafb74d9ae1b31d17d4c3df8255e5a130acf03f3495",
    ),
    "expected": (
        "MIZAN_CONTRACT_R_POSITIVE_EXPECTED_CONTENT_02.json",
        "d83a727971abd8f5af4f0250a5ca79a689876584d030312cd88bfcc57e99c240",
    ),
}
SECTION_ORDER = (
    "vision", "pillars", "environment", "gaps", "roadmap", "kpis",
    "confidence", "governance", "traceability",
)
REQUIRED_COLUMNS = {
    "users": {"id", "username", "email", "password_hash", "role", "is_active", "last_login"},
    "strategies": {
        "id", "user_id", "domain", "language", "generation_mode", "artifact_status",
        "publishability_score", "org_name", "sector", "document_title", "content",
        "content_json", "sections_json",
    },
    "traceability_records": {
        "user_id", "artifact_type", "artifact_id", "section_key", "source_frameworks",
        "evidence_sufficiency", "linked_kpis", "linked_roadmap_tasks",
    },
    "export_tasks": {"task_id", "user_id", "record_id", "fmt", "filename", "status", "tmp", "error", "diag"},
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def inside(path, parent):
    return path == parent or parent in path.parents


def write_new_json(path, value, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def password_hash(password):
    # Exact production verify_password format (app.py:1391-1410).
    salt = secrets.token_hex(16)
    raw = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return salt + "$" + raw.hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--private-output", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    database = args.database.resolve(strict=True)
    output = args.output.resolve()
    private_output = args.private_output.resolve()
    if not database.is_file() or inside(database, source):
        raise ValueError("Database must be an existing disposable file outside the checkout")
    if any(inside(path, source) for path in (output, private_output)):
        raise ValueError("Bootstrap output paths must be outside the checkout")
    if output == private_output or inside(private_output, output.parent):
        raise ValueError("Private credentials must be outside the public evidence directory")
    if output.exists() or private_output.exists() or database in (output, private_output):
        raise ValueError("Bootstrap outputs must be new paths distinct from the database")
    head = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True, timeout=15,
    ).stdout.strip()
    if head != EXPECTED_HEAD:
        raise ValueError("Source HEAD is not the reviewed PR head")

    fixture_dir = source / "tests" / "fixtures" / "mizan_contract_r"
    raw = {}
    fixture_receipt = {}
    for role, (name, expected_hash) in FIXTURES.items():
        path = fixture_dir / name
        data = path.read_bytes()
        if digest(data) != expected_hash:
            raise ValueError("Fixture identity mismatch: " + name)
        raw[role] = data
        fixture_receipt[role] = {"path": str(path), "bytes": len(data), "sha256": expected_hash}
    if b"\r" in raw["body"] or not raw["body"].endswith(b"\n"):
        raise ValueError("Fixture body newline identity mismatch")
    text = raw["body"].decode("utf-8")
    expected = json.loads(raw["expected"].decode("utf-8"))
    sections = {}
    for key in SECTION_ORDER:
        item = expected["saved_sections"][key]
        value = item["text"] if isinstance(item, dict) else item
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Missing fixture section: " + key)
        sections[key] = value
    sections["_document_type"] = "strategy"
    sections_json = json.dumps(sections, ensure_ascii=False)
    specification = expected["database_specification"]
    strategy = specification["strategies_candidate"]
    trace = specification["traceability_records_gate_row"]
    if (strategy["id"], strategy["user_id"], strategy["language"],
            strategy["generation_mode"], strategy["artifact_status"]) != (
            702, 7, "ar", "consulting", "publishable"):
        raise ValueError("Unexpected stored fixture metadata")

    users = {
        "owner": {"id": 7, "username": "mizan_owner7", "password": secrets.token_urlsafe(32)},
        "other": {"id": 8, "username": "mizan_other8", "password": secrets.token_urlsafe(32)},
    }
    values = (
        702, 7, strategy["domain"], strategy["language"], strategy["generation_mode"],
        strategy["artifact_status"], strategy["publishability_score"], strategy["org_name"],
        strategy["sector"], strategy["document_title"], text, None, sections_json,
    )
    payload = {
        "content": text, "language": "ar", "org_name": strategy["org_name"],
        "sector": strategy["sector"], "doc_type": "strategy",
        "domain": "Digital Transformation", "selected_frameworks": ["DGA"],
        "artifact_id": 702, "strategy_id": 702, "artifact_type": "strategy",
        "document_type": "strategy", "generation_mode": "consulting",
    }
    private = {
        "source_head": head, "database": str(database), "users": users,
        "payloads": {fmt: dict(payload, filename="mizan-native-702-" + fmt) for fmt in ("docx", "pdf")},
        "expected_markers": ["KPI-DT-POS-01", "RM-DT-POS-01", "API v2.1", "99.5%"],
        "expected_markers_scope": "Fixture-derived inspection inputs, not a complete visual or raw-reference oracle",
    }
    for marker in private["expected_markers"]:
        if marker not in text:
            raise ValueError("Inspection marker is absent from the accepted fixture")

    # mode=rw cannot silently create another database if the target disappears.
    conn = sqlite3.connect(database.as_uri() + "?mode=rw", uri=True, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    private_written = False
    committed = False
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise ValueError("Foreign-key enforcement is unavailable")
        journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
        if str(journal).lower() != "wal":
            raise ValueError("Expected the real application's initialized WAL database")
        schema = {}
        for table, required in REQUIRED_COLUMNS.items():
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(" + table + ")")}
            if not required <= columns:
                raise ValueError("Application schema is not initialized: " + table)
            schema[table] = sorted(columns)
        conn.execute("BEGIN IMMEDIATE")
        for table in ("strategies", "traceability_records", "export_tasks"):
            if conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]:
                raise ValueError("Refusing to seed a nonempty disposable artifact table: " + table)
        if conn.execute(
            "SELECT 1 FROM users WHERE id IN (7,8) OR username IN (?,?) OR email IN (?,?)",
            ("mizan_owner7", "mizan_other8", "mizan_owner7@example.invalid", "mizan_other8@example.invalid"),
        ).fetchone():
            raise ValueError("Fixture user ID, username, or email already exists")
        for user in users.values():
            conn.execute(
                "INSERT INTO users(id,username,email,password_hash,role,is_active) VALUES(?,?,?,?,?,?)",
                (user["id"], user["username"], user["username"] + "@example.invalid",
                 password_hash(user["password"]), "user", 1),
            )
        conn.execute(
            "INSERT INTO strategies(id,user_id,domain,language,generation_mode,artifact_status,"
            "publishability_score,org_name,sector,document_title,content,content_json,sections_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", values,
        )
        trace_values = (
            7, "strategy", 702, trace["section_key"], trace["source_frameworks"],
            trace["evidence_sufficiency"], trace["linked_kpis"], trace["linked_roadmap_tasks"],
        )
        conn.execute(
            "INSERT INTO traceability_records(user_id,artifact_type,artifact_id,section_key,"
            "source_frameworks,evidence_sufficiency,linked_kpis,linked_roadmap_tasks) VALUES(?,?,?,?,?,?,?,?)",
            trace_values,
        )
        row = conn.execute(
            "SELECT id,user_id,domain,language,generation_mode,artifact_status,publishability_score,"
            "org_name,sector,document_title,content,content_json,sections_json FROM strategies WHERE id=702",
        ).fetchone()
        if tuple(row) != values:
            raise ValueError("Seeded strategy failed exact metadata/body round-trip verification")
        trace_rows = conn.execute(
            "SELECT user_id,artifact_type,artifact_id,section_key,source_frameworks,"
            "evidence_sufficiency,linked_kpis,linked_roadmap_tasks FROM traceability_records "
            "WHERE user_id=7 AND artifact_type='strategy' AND artifact_id=702",
        ).fetchall()
        if len(trace_rows) != 1 or tuple(trace_rows[0]) != trace_values:
            raise ValueError("Seeded traceability failed exact round-trip verification")
        stored_trace = dict(trace_rows[0])
        if conn.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError("Foreign-key check failed")
        # Prepare credentials before COMMIT; remove them if the transaction fails.
        write_new_json(private_output, private)
        private_written = True
        conn.execute("COMMIT")
        committed = True
    finally:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        conn.close()
        if private_written and not committed:
            private_output.unlink(missing_ok=True)

    receipt = {
        "seed_succeeded": True, "source_head": head, "database": str(database),
        "caller_precondition": "Both real Gunicorn post_worker_init events must have been observed before invocation",
        "application_imported_by_seeder": False, "database_schema_created_by_seeder": False,
        "schema_columns_observed": schema, "journal_mode": journal, "foreign_keys": True,
        "fixtures": fixture_receipt,
        "users": [{"id": value["id"], "username": value["username"], "role": "user", "is_active": 1}
                  for value in users.values()],
        "credential_scope": "Random disposable real-login credentials exist only in the separate private bootstrap file",
        "stored_strategy": {
            "id": 702, "user_id": 7, "metadata": {key: strategy[key] for key in (
                "domain", "language", "generation_mode", "artifact_status", "publishability_score",
                "org_name", "sector", "document_title")},
            "content_sha256": digest(text.encode("utf-8")),
            "sections_json_sha256": digest(sections_json.encode("utf-8")),
            "sections_json_keys": list(sections), "content_json": None,
        },
        "traceability": stored_trace,
        "stored_strategy_round_trip_verified": True,
        "stored_traceability_round_trip_verified": True,
        "negative_task_rows_seeded": False,
    }
    write_new_json(output, receipt)
    print(json.dumps({"seed_succeeded": True, "public_receipt": str(output)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
