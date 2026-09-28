"""Per-user, per-document-type, per-domain document-limit override.

Uses an isolated SQLite file and provider stubs. No live model call.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_IMPORT_TMP = tempfile.mkdtemp(prefix="test_rel37_doc_limits_import_")
if "app" not in sys.modules:
    os.environ["ADMIN_PASSWORD"] = "test-admin-password"
    os.environ["SECRET_KEY"] = "test-secret-key"
    os.environ["DATABASE_PATH"] = os.path.join(_IMPORT_TMP, "import.db")
    os.environ["DATABASE_URL"] = "sqlite:///" + os.environ["DATABASE_PATH"]
    os.environ["ANTHROPIC_API_KEY"] = ""
    os.environ["OPENAI_API_KEY"] = ""
    os.environ["GOOGLE_API_KEY"] = ""
    os.environ["GROQ_API_KEY"] = ""
    os.environ["DEEPSEEK_API_KEY"] = ""
else:
    os.environ.setdefault("ADMIN_PASSWORD", "test-admin-password")

import app as app_mod  # noqa: E402


_PROVIDER_FUNCS = (
    "_generate_anthropic",
    "_generate_openai",
    "_generate_google",
    "_generate_groq",
    "_generate_deepseek",
)
_CONFIG_KEYS = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "GROQ_API_KEY",
    "DEEPSEEK_API_KEY",
    "AI_PROVIDER",
)


class DocumentLimitTests(unittest.TestCase):
    def setUp(self):
        self._prev_db = app_mod.config.DB_PATH
        self._prev_testing = os.environ.get("TESTING")
        self._tmpdir = tempfile.mkdtemp(prefix="test_rel37_doc_limits_")
        self.db_path = os.path.join(self._tmpdir, "limits.db")
        app_mod.config.DB_PATH = self.db_path
        os.environ["TESTING"] = "1"
        self._prev_config = {key: getattr(app_mod.config, key) for key in _CONFIG_KEYS}
        app_mod.config.ANTHROPIC_API_KEY = "test-mock-key-not-real"
        app_mod.config.OPENAI_API_KEY = ""
        app_mod.config.GOOGLE_API_KEY = ""
        app_mod.config.GROQ_API_KEY = ""
        app_mod.config.DEEPSEEK_API_KEY = ""
        app_mod.config.AI_PROVIDER = "anthropic"
        app_mod.init_db()
        self.csrf = "csrf-doc-limit"
        self._next_id = 50

    def tearDown(self):
        app_mod.config.DB_PATH = self._prev_db
        for key, value in self._prev_config.items():
            setattr(app_mod.config, key, value)
        if self._prev_testing is None:
            os.environ.pop("TESTING", None)
        else:
            os.environ["TESTING"] = self._prev_testing

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _user(self, username, role="user", token_usage=0, token_limit=500000, user_id=None):
        if user_id is None:
            user_id = self._next_id
            self._next_id += 1
        conn = self._conn()
        conn.execute(
            "INSERT INTO users (id, username, email, password_hash, role, is_active, "
            "token_usage, token_limit) VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
            (user_id, username, f"{username}@limits.local", "not-a-password",
             role, token_usage, token_limit),
        )
        conn.commit()
        conn.close()
        return user_id

    def _insert_docs(self, table, user_id, count, domain, procedure=False):
        conn = self._conn()
        for _ in range(count):
            if table == "strategies":
                conn.execute(
                    "INSERT INTO strategies (user_id, domain, org_name, sector, content, language) "
                    "VALUES (?, ?, 'Org', 'Government', 'fixture', 'en')",
                    (user_id, domain),
                )
            elif table == "policies":
                conn.execute(
                    "INSERT INTO policies (user_id, domain, policy_name, framework, content, "
                    "language, is_procedure) VALUES (?, ?, 'Policy', 'NCA ECC', 'fixture', 'en', ?)",
                    (user_id, domain, 1 if procedure else 0),
                )
            elif table == "audits":
                conn.execute(
                    "INSERT INTO audits (user_id, domain, framework, scope, content, language) "
                    "VALUES (?, ?, 'NCA ECC', 'full', 'fixture', 'en')",
                    (user_id, domain),
                )
            elif table == "risks":
                conn.execute(
                    "INSERT INTO risks (user_id, domain, asset_name, threat, risk_level, analysis, language) "
                    "VALUES (?, ?, 'asset', 'threat', 'low', 'fixture', 'en')",
                    (user_id, domain),
                )
            else:
                raise AssertionError(table)
        conn.commit()
        conn.close()

    def _override_row(self, user_id, doc_type, domain_code, limit_value):
        conn = self._conn()
        conn.execute(
            "INSERT INTO user_domain_doc_limits (user_id, doc_type, domain_code, limit_value) "
            "VALUES (?, ?, ?, ?)",
            (user_id, doc_type, domain_code, limit_value),
        )
        conn.commit()
        conn.close()

    def _limit_rows(self):
        conn = self._conn()
        rows = conn.execute(
            "SELECT user_id, doc_type, domain_code, limit_value FROM user_domain_doc_limits "
            "ORDER BY user_id, doc_type, domain_code"
        ).fetchall()
        conn.close()
        return [tuple(row) for row in rows]

    def _count(self, table, user_id, domain):
        with app_mod.app.app_context():
            usage = app_mod.get_user_usage_by_domain(user_id, domain)
        return usage[table]

    def _check(self, user_id, doc_type, domain):
        with app_mod.app.app_context():
            return app_mod.check_usage_limit(user_id, doc_type, domain)

    def _remaining(self, user_id, domain):
        with app_mod.app.app_context():
            return app_mod.get_remaining_usage(user_id, domain)

    def _client(self, user_id, role):
        client = app_mod.app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = f"user-{user_id}"
            sess["role"] = role
            sess["csrf_token"] = self.csrf
        return client

    def _strategy_body(self, domain="Cyber Security", **extra):
        body = {
            "domain": domain,
            "language": "en",
            "org_name": "Quota Org",
            "sector": "Government",
            "size": "Medium (100-1000)",
            "budget": "1M-5M SAR",
            "frameworks": ["NCA ECC (Essential Cybersecurity Controls)"],
            "org_structure": "centralized",
            "technologies": ["SIEM"],
            "maturity_level": "developing",
            "challenges": "quota fixture",
            "doc_subtype": "technical",
            "generation_mode": "drafting",
            "diagnostic_id": None,
            "csrf_token": self.csrf,
        }
        body.update(extra)
        return body

    def _headers(self, token=None):
        headers = {}
        if token is not None:
            headers["X-CSRFToken"] = token
        return headers

    def test_default_limit_and_shared_language_count(self):
        uid = self._user("default-user")
        self.assertEqual(self._limit_rows(), [])
        allowed, used, limit = self._check(uid, "strategies", "Cyber Security")
        self.assertEqual((allowed, used, limit), (True, 0, 10))
        self._insert_docs("strategies", uid, 6, "Cyber Security")
        self._insert_docs("strategies", uid, 4, "الأمن السيبراني")
        allowed, used, limit = self._check(uid, "strategies", "cybersecurity")
        self.assertEqual((allowed, used, limit), (False, 10, 10))
        allowed_ar, used_ar, limit_ar = self._check(uid, "strategies", "الأمن السيبراني")
        self.assertEqual((allowed_ar, used_ar, limit_ar), (False, 10, 10))
        remaining = self._remaining(uid, "cyber_security")
        self.assertEqual(remaining["strategies"]["limit"], 10)
        self.assertEqual(remaining["strategies"]["used"], 10)
        self.assertEqual(remaining["strategies"]["remaining"], 0)
        self.assertEqual(remaining["strategies"]["limit_source"], "default")
        self.assertEqual(app_mod.USAGE_LIMITS["strategies"], 10)

    def test_override_18_reaches_cap_and_refuses_the_next_save(self):
        uid = self._user("cap-18")
        self._insert_docs("strategies", uid, 8, "Cyber Security")
        self._override_row(uid, "strategies", "cyber", 18)
        saved = 8
        while True:
            allowed, used, limit = self._check(uid, "strategies", "Cyber Security")
            self.assertEqual(limit, 18)
            self.assertEqual(used, saved)
            if not allowed:
                break
            self._insert_docs("strategies", uid, 1, "الأمن السيبراني")
            saved += 1
            self.assertLessEqual(saved, 18)
        self.assertEqual(saved, 18)
        self.assertEqual(self._count("strategies", uid, "cybersecurity"), 18)
        allowed, used, limit = self._check(uid, "strategies", "الأمن السيبراني")
        self.assertEqual((allowed, used, limit), (False, 18, 18))

    def test_override_19_allows_nineteenth_and_refuses_twentieth(self):
        uid = self._user("cap-19")
        self._insert_docs("strategies", uid, 18, "Cyber Security")
        self._override_row(uid, "strategies", "cyber", 19)
        allowed, used, limit = self._check(uid, "strategies", "Cyber Security")
        self.assertEqual((allowed, used, limit), (True, 18, 19))
        self._insert_docs("strategies", uid, 1, "الأمن السيبراني")
        allowed, used, limit = self._check(uid, "strategies", "cyber_security")
        self.assertEqual((allowed, used, limit), (False, 19, 19))
        remaining = self._remaining(uid, "الأمن السيبراني")
        self.assertEqual(remaining["strategies"]["remaining"], 0)

    def test_override_is_isolated_by_user_domain_and_type(self):
        owner = self._user("owner")
        other = self._user("other")
        self._override_row(owner, "strategies", "cyber", 19)
        self._insert_docs("strategies", owner, 8, "Cyber Security")
        self._insert_docs("strategies", owner, 10, "Data Management")
        self._insert_docs("policies", owner, 10, "Cyber Security")
        self._insert_docs("policies", owner, 10, "Cyber Security", procedure=True)
        self._insert_docs("audits", owner, 10, "الأمن السيبراني")
        self._insert_docs("risks", owner, 10, "Cyber Security")
        self._insert_docs("strategies", other, 10, "Cyber Security")

        self.assertEqual(self._check(owner, "strategies", "Cyber Security")[:3], (True, 8, 19))
        self.assertEqual(self._check(other, "strategies", "الأمن السيبراني"), (False, 10, 10))
        self.assertEqual(self._check(owner, "strategies", "Data Management"), (False, 10, 10))
        self.assertEqual(self._check(owner, "policies", "cybersecurity"), (False, 10, 10))
        self.assertEqual(self._check(owner, "procedures", "Cyber Security"), (False, 10, 10))
        self.assertEqual(self._check(owner, "audits", "cyber"), (False, 10, 10))
        self.assertEqual(self._check(owner, "risks", "الأمن السيبراني"), (False, 10, 10))
        data_remaining = self._remaining(owner, "data")
        self.assertEqual(data_remaining["strategies"]["limit_source"], "default")
        self.assertEqual(data_remaining["strategies"]["limit"], 10)
        prefix = self._remaining(owner, "cyb")
        self.assertEqual(prefix["strategies"]["limit_source"], "default")
        self.assertEqual(prefix["strategies"]["used"], 0)
        self.assertEqual(prefix["strategies"]["limit"], 10)

    def test_reporting_agrees_and_zero_is_not_a_missing_override(self):
        uid = self._user("report")
        self._insert_docs("strategies", uid, 8, "Cyber Security")
        self._override_row(uid, "strategies", "cyber", 19)
        remaining = self._remaining(uid, "Cyber Security")
        self.assertEqual(remaining["strategies"], {
            "used": 8,
            "limit": 19,
            "remaining": 11,
            "limit_source": "override",
        })
        client = self._client(uid, "user")
        api = client.get("/api/usage/" + quote("Cyber Security"))
        self.assertEqual(api.status_code, 200)
        body = api.get_json()["usage"]["strategies"]
        self.assertEqual(body["used"], 8)
        self.assertEqual(body["limit"], 19)
        self.assertEqual(body["remaining"], 11)
        arabic = client.get("/api/usage/" + quote("الأمن السيبراني"))
        self.assertEqual(arabic.get_json()["usage"]["strategies"]["remaining"], 11)
        alias = client.get("/api/usage/cybersecurity")
        self.assertEqual(alias.get_json()["usage"]["strategies"]["used"], 8)
        self.assertEqual(alias.get_json()["usage"]["strategies"]["limit"], 19)
        page = client.get("/domain/" + quote("Cyber Security"))
        self.assertEqual(page.status_code, 200, page.get_data(as_text=True)[:300])
        self.assertIn("8/19", page.get_data(as_text=True))
        allowed, used, limit = self._check(uid, "strategies", "Cyber Security")
        self.assertEqual((allowed, used, limit), (True, 8, 19))

        zero_user = self._user("zero-cap")
        self._override_row(zero_user, "strategies", "cyber", 0)
        allowed, used, limit = self._check(zero_user, "strategies", "Cyber Security")
        self.assertEqual((allowed, used, limit), (False, 0, 0))
        zero_remaining = self._remaining(zero_user, "cyber")
        self.assertEqual(zero_remaining["strategies"]["limit"], 0)
        self.assertEqual(zero_remaining["strategies"]["remaining"], 0)
        self.assertEqual(zero_remaining["strategies"]["limit_source"], "override")
        over = self._user("over-count")
        self._insert_docs("strategies", over, 12, "Data Management")
        over_remaining = self._remaining(over, "Data Management")
        self.assertEqual(over_remaining["strategies"]["remaining"], 0)
        self.assertGreaterEqual(over_remaining["strategies"]["remaining"], 0)

    def _assert_limit_unavailable(self, user_id, domain="Cyber Security"):
        with self.assertRaises(app_mod.DocumentLimitError):
            self._check(user_id, "strategies", domain)
        remaining = self._remaining(user_id, domain)["strategies"]
        self.assertEqual(remaining["limit_source"], "unavailable")
        self.assertNotIn(remaining["limit_source"], ("default", "override"))

    def test_malformed_override_and_lookup_failure_deny_access(self):
        uid = self._user("malformed")
        self._override_row(uid, "strategies", "cyber", -1)
        self._assert_limit_unavailable(uid)
        remaining = self._remaining(uid, "Cyber Security")["strategies"]
        self.assertEqual(remaining["remaining"], 0)
        self.assertNotEqual(remaining["limit"], 10)

        conn = self._conn()
        conn.execute(
            "UPDATE user_domain_doc_limits SET limit_value = ? WHERE user_id = ?",
            ("not-an-int", uid),
        )
        conn.commit()
        conn.close()
        self._assert_limit_unavailable(uid, "cyber")

        conn = self._conn()
        conn.execute("DROP TABLE user_domain_doc_limits")
        conn.commit()
        conn.close()
        self._assert_limit_unavailable(uid)

    def test_migration_is_empty_and_repeatable(self):
        conn = self._conn()
        conn.execute("DROP TABLE user_domain_doc_limits")
        conn.execute(
            "INSERT INTO users (id, username, email, password_hash, role, is_active, "
            "token_usage, token_limit) VALUES (2, 'local-existing', 'local-existing@limits.local', "
            "'not-a-password', 'user', 1, 500643, 1250643)"
        )
        for _ in range(8):
            conn.execute(
                "INSERT INTO strategies (user_id, domain, content, language) "
                "VALUES (2, 'Cyber Security', 'historical', 'en')"
            )
        conn.commit()
        before_tokens = conn.execute(
            "SELECT token_usage, token_limit FROM users WHERE id = 2"
        ).fetchone()
        before_docs = conn.execute(
            "SELECT COUNT(*) FROM strategies WHERE user_id = 2"
        ).fetchone()[0]
        conn.close()

        app_mod.init_db()
        app_mod.init_db()
        conn = self._conn()
        overrides = conn.execute("SELECT COUNT(*) FROM user_domain_doc_limits").fetchone()[0]
        tokens = conn.execute(
            "SELECT token_usage, token_limit FROM users WHERE id = 2"
        ).fetchone()
        docs = conn.execute(
            "SELECT COUNT(*) FROM strategies WHERE user_id = 2"
        ).fetchone()[0]
        named = conn.execute(
            "SELECT COUNT(*) FROM users WHERE username = 'rel37stdA'"
        ).fetchone()[0]
        conn.close()
        self.assertEqual(overrides, 0)
        self.assertEqual(tuple(before_tokens), (500643, 1250643))
        self.assertEqual(tuple(tokens), (500643, 1250643))
        self.assertEqual(before_docs, 8)
        self.assertEqual(docs, 8)
        self.assertEqual(named, 0)

        fresh = os.path.join(self._tmpdir, "fresh.db")
        previous = app_mod.config.DB_PATH
        app_mod.config.DB_PATH = fresh
        try:
            app_mod.init_db()
            raw = sqlite3.connect(fresh)
            count = raw.execute("SELECT COUNT(*) FROM user_domain_doc_limits").fetchone()[0]
            tables = raw.execute(
                "SELECT sql FROM sqlite_master WHERE name = 'user_domain_doc_limits'"
            ).fetchone()[0]
            raw.close()
        finally:
            app_mod.config.DB_PATH = previous
        self.assertEqual(count, 0)
        self.assertIn("PRIMARY KEY (user_id, doc_type, domain_code)", tables)
        self.assertIn("REFERENCES users(id)", tables)

    def test_admin_absolute_upsert_is_idempotent_and_audited(self):
        admin = self._user("limit-admin", role="admin")
        target = self._user("limit-target", token_usage=500643, token_limit=1250643)
        self._insert_docs("strategies", target, 8, "Cyber Security")
        client = self._client(admin, "admin")
        payload = {
            "doc_type": "strategies",
            "domain": "الأمن السيبراني",
            "limit_value": 19,
            "reason": "campaign-authorization-ref",
            "csrf_token": self.csrf,
        }
        first = client.post(
            f"/admin/api/users/{target}/document-limit",
            json=payload,
            headers=self._headers(self.csrf),
        )
        self.assertEqual(first.status_code, 200, first.get_data(as_text=True)[:400])
        body = first.get_json()
        self.assertEqual(body["limit"], 19)
        self.assertEqual(body["used"], 8)
        self.assertEqual(body["remaining"], 11)
        self.assertEqual(body["limit_source"], "override")
        self.assertIsNone(body["previous_limit"])
        self.assertEqual(body["domain_code"], "cyber")
        second = client.post(
            f"/admin/api/users/{target}/document-limit",
            json={**payload, "domain": "cybersecurity"},
            headers=self._headers(self.csrf),
        )
        self.assertEqual(second.status_code, 200, second.get_data(as_text=True)[:400])
        self.assertEqual(second.get_json()["previous_limit"], 19)
        self.assertEqual(second.get_json()["limit"], 19)
        self.assertEqual(self._limit_rows(), [(target, "strategies", "cyber", 19)])
        conn = self._conn()
        tokens = conn.execute(
            "SELECT token_usage, token_limit FROM users WHERE id = ?", (target,)
        ).fetchone()
        docs = conn.execute(
            "SELECT COUNT(*) FROM strategies WHERE user_id = ?", (target,)
        ).fetchone()[0]
        audits = conn.execute(
            "SELECT user_id, action, metadata, created_at FROM audit_logs "
            "WHERE action = 'set_document_limit' ORDER BY id"
        ).fetchall()
        conn.close()
        self.assertEqual(tuple(tokens), (500643, 1250643))
        self.assertEqual(docs, 8)
        self.assertEqual(len(audits), 2)
        meta = json.loads(audits[-1]["metadata"])
        self.assertEqual(meta["actor_user_id"], admin)
        self.assertEqual(meta["target_user_id"], target)
        self.assertEqual(meta["target_username"], "limit-target")
        self.assertEqual(meta["doc_type"], "strategies")
        self.assertEqual(meta["domain_code"], "cyber")
        self.assertEqual(meta["old_limit"], 19)
        self.assertEqual(meta["new_limit"], 19)
        self.assertEqual(meta["reason"], "campaign-authorization-ref")
        self.assertTrue(audits[-1]["created_at"])
        blob = json.dumps(meta)
        self.assertNotIn(self.csrf, blob)
        self.assertNotIn("not-a-password", blob)
        self.assertNotIn("test-mock-key", blob)

    def test_rejected_admin_writes_do_not_mutate(self):
        admin = self._user("writer-admin", role="admin")
        target = self._user("writer-target")
        self._override_row(target, "strategies", "cyber", 19)
        before = self._limit_rows()
        client = self._client(admin, "admin")
        invalid = [
            {"doc_type": "strategies", "domain": "cyber", "limit_value": True},
            {"doc_type": "strategies", "domain": "cyber", "limit_value": 19.5},
            {"doc_type": "strategies", "domain": "cyber", "limit_value": "19"},
            {"doc_type": "strategies", "domain": "cyber", "limit_value": None},
            {"doc_type": "strategies", "domain": "cyber", "limit_value": -1},
            {"doc_type": "strategies", "domain": "cyber", "limit_value": 9223372036854775808},
            {"doc_type": "strategies", "domain": "cyber"},
            {"doc_type": "strategy", "domain": "cyber", "limit_value": 19},
            {"doc_type": "strategies", "domain": "cyb", "limit_value": 19},
            {"doc_type": "strategies", "domain": None, "limit_value": 19},
            {"doc_type": "strategies", "domain": "cyber", "limit_value": 4, "reason": {"x": 1}},
            {"doc_type": "strategies", "domain": "cyber", "limit_value": 4, "reason": "x" * 201},
            [],
        ]
        for payload in invalid:
            response = client.post(
                f"/admin/api/users/{target}/document-limit",
                json=payload,
                headers=self._headers(self.csrf),
            )
            self.assertEqual(response.status_code, 400, payload)
            self.assertFalse(response.get_json()["success"])
        missing_user = client.post(
            "/admin/api/users/99999/document-limit",
            json={"doc_type": "strategies", "domain": "cyber", "limit_value": 4},
            headers=self._headers(self.csrf),
        )
        self.assertEqual(missing_user.status_code, 404)
        self.assertEqual(self._limit_rows(), before)

        stranger = self._user("stranger", role="user")
        denied = self._client(stranger, "user").post(
            f"/admin/api/users/{target}/document-limit",
            json={"doc_type": "strategies", "domain": "cyber", "limit_value": 4},
            headers=self._headers(self.csrf),
        )
        self.assertEqual(denied.status_code, 403)
        self_grant = self._client(target, "user").post(
            f"/admin/api/users/{target}/document-limit",
            json={"doc_type": "strategies", "domain": "cyber", "limit_value": 30},
            headers=self._headers(self.csrf),
        )
        self.assertEqual(self_grant.status_code, 403)

        anonymous = app_mod.app.test_client().post(
            f"/admin/api/users/{target}/document-limit",
            json={"doc_type": "strategies", "domain": "cyber", "limit_value": 4,
                  "csrf_token": self.csrf},
        )
        self.assertIn(anonymous.status_code, (302, 401, 403))
        stale = client.post(
            f"/admin/api/users/{target}/document-limit",
            json={"doc_type": "strategies", "domain": "cyber", "limit_value": 4},
            headers=self._headers("stale-token"),
        )
        self.assertEqual(stale.status_code, 403)
        missing_csrf = client.post(
            f"/admin/api/users/{target}/document-limit",
            json={"doc_type": "strategies", "domain": "cyber", "limit_value": 4},
        )
        self.assertEqual(missing_csrf.status_code, 403)
        self.assertEqual(self._limit_rows(), before)

        raw = self._conn()
        with self.assertRaises(sqlite3.IntegrityError):
            raw.execute(
                "INSERT INTO user_domain_doc_limits (user_id, doc_type, domain_code, limit_value) "
                "VALUES (424242, 'strategies', 'cyber', 19)"
            )
            raw.commit()
        raw.close()

    def test_routes_honor_the_cap_without_calling_the_provider(self):
        uid = self._user("route-user")
        self._override_row(uid, "strategies", "cyber", 19)
        self._insert_docs("strategies", uid, 8, "Cyber Security")
        client = self._client(uid, "user")
        calls = []
        originals = {name: getattr(app_mod, name) for name in _PROVIDER_FUNCS}

        def _fake(name):
            def _inner(*_args, **_kwargs):
                calls.append(name)
                raise RuntimeError("provider_mock_blocked")
            return _inner

        captured = []
        real_thread = threading.Thread

        def _capture(*args, **kwargs):
            thread = real_thread(*args, **kwargs)
            captured.append(thread)
            return thread

        for name in _PROVIDER_FUNCS:
            setattr(app_mod, name, _fake(name))
        threading.Thread = _capture
        try:
            async_ok = client.post(
                "/api/generate-strategy-async",
                json=self._strategy_body(),
                headers=self._headers(self.csrf),
            )
            self.assertEqual(async_ok.status_code, 200, async_ok.get_data(as_text=True)[:500])
            self.assertEqual(len(captured), 1)
            captured[0].join(timeout=120)
            self.assertFalse(captured[0].is_alive(), "async worker still pending")
            status = client.get("/api/strategy-status/" + async_ok.get_json()["task_id"])
            self.assertNotIn(status.get_json().get("status"), ("pending", "running"))
            self.assertTrue(calls, "allowed async admission did not reach the provider mock")
            calls.clear()
            captured.clear()

            sync_ok = client.post(
                "/api/generate-strategy",
                json=self._strategy_body(domain="cybersecurity"),
                headers=self._headers(self.csrf),
            )
            self.assertNotEqual(sync_ok.status_code, 429, sync_ok.get_data(as_text=True)[:400])
            self.assertTrue(calls, "allowed sync admission did not reach the provider mock")
            calls.clear()

            bilingual_ok = client.post(
                "/api/generate-bilingual",
                json={"type": "strategy", "domain": "الأمن السيبراني", "csrf_token": self.csrf},
                headers=self._headers(self.csrf),
            )
            self.assertNotEqual(bilingual_ok.status_code, 429, bilingual_ok.get_data(as_text=True)[:400])
            self.assertTrue(calls, "allowed bilingual admission did not reach the provider mock")
            calls.clear()

            used_now = self._count("strategies", uid, "Cyber Security")
            self._insert_docs("strategies", uid, 19 - used_now, "Cyber Security")
            self.assertEqual(self._count("strategies", uid, "Cyber Security"), 19)
            before_calls = list(calls)
            async_no = client.post(
                "/api/generate-strategy-async",
                json=self._strategy_body(domain="الأمن السيبراني", user_id=1, limit=100),
                headers=self._headers(self.csrf),
            )
            sync_no = client.post(
                "/api/generate-strategy",
                json=self._strategy_body(domain="cyber_security", user_id=999, table="policies"),
                headers=self._headers(self.csrf),
            )
            bilingual_no = client.post(
                "/api/generate-bilingual",
                json={"type": "strategy", "domain": "cybersecurity", "user_id": 1},
                headers=self._headers(self.csrf),
            )
            self.assertEqual(async_no.status_code, 429, async_no.get_data(as_text=True)[:400])
            self.assertEqual(sync_no.status_code, 429, sync_no.get_data(as_text=True)[:400])
            self.assertEqual(bilingual_no.status_code, 429, bilingual_no.get_data(as_text=True)[:400])
            self.assertEqual(calls, before_calls)
            self.assertEqual(captured, [])

            unknown = client.post(
                "/api/generate-bilingual",
                json={"type": "strategies", "domain": "Data Management"},
                headers=self._headers(self.csrf),
            )
            self.assertEqual(unknown.status_code, 400, unknown.get_data(as_text=True)[:300])
            bad_domain = client.post(
                "/api/generate-bilingual",
                json={"type": "policy", "domain": "cyb"},
                headers=self._headers(self.csrf),
            )
            self.assertEqual(bad_domain.status_code, 400)
            self.assertEqual(calls, before_calls)

            self._insert_docs("strategies", uid, 10, "Data Management")
            data_denied = client.post(
                "/api/generate-strategy",
                json=self._strategy_body(domain="Data Management"),
                headers=self._headers(self.csrf),
            )
            self.assertEqual(data_denied.status_code, 429, data_denied.get_data(as_text=True)[:300])
            self.assertEqual(calls, before_calls)
        finally:
            threading.Thread = real_thread
            for name, func in originals.items():
                setattr(app_mod, name, func)
            for thread in captured:
                thread.join(timeout=5)

    def test_async_limit_lookup_failure_does_not_start_generation(self):
        uid = self._user("fail-closed")
        client = self._client(uid, "user")
        calls = []

        def _explode(*_args, **_kwargs):
            raise RuntimeError("limit store unavailable")

        original = app_mod.check_usage_limit
        app_mod.check_usage_limit = _explode
        captured = []
        real_thread = threading.Thread

        def _capture(*args, **kwargs):
            captured.append(1)
            return real_thread(*args, **kwargs)

        threading.Thread = _capture
        try:
            response = client.post(
                "/api/generate-strategy-async",
                json=self._strategy_body(),
                headers=self._headers(self.csrf),
            )
        finally:
            app_mod.check_usage_limit = original
            threading.Thread = real_thread
        self.assertEqual(response.status_code, 503, response.get_data(as_text=True)[:400])
        self.assertTrue(response.get_json().get("limit_check_failed"))
        self.assertEqual(captured, [])
        self.assertEqual(calls, [])

    def test_exhausted_token_quota_blocks_with_document_slots_left(self):
        uid = self._user("token-empty", token_usage=1250643, token_limit=1250643)
        self._override_row(uid, "strategies", "cyber", 19)
        allowed, used, limit = self._check(uid, "strategies", "Cyber Security")
        self.assertEqual((allowed, used, limit), (True, 0, 19))
        calls = []
        originals = {name: getattr(app_mod, name) for name in _PROVIDER_FUNCS}

        def _fake(name):
            def _inner(*_args, **_kwargs):
                calls.append(name)
                raise RuntimeError("provider_mock_blocked")
            return _inner

        for name in _PROVIDER_FUNCS:
            setattr(app_mod, name, _fake(name))
        try:
            with app_mod.app.test_request_context("/api/generate-strategy", method="POST"):
                from flask import session
                session["user_id"] = uid
                text = app_mod.generate_ai_content("prompt", "en", content_type="strategy")
        finally:
            for name, func in originals.items():
                setattr(app_mod, name, func)
        self.assertIn("Token Quota Exceeded", text)
        self.assertEqual(calls, [])
        conn = self._conn()
        usage = conn.execute(
            "SELECT token_usage, token_limit FROM users WHERE id = ?", (uid,)
        ).fetchone()
        docs = conn.execute(
            "SELECT COUNT(*) FROM strategies WHERE user_id = ?", (uid,)
        ).fetchone()[0]
        conn.close()
        self.assertEqual(tuple(usage), (1250643, 1250643))
        self.assertEqual(docs, 0)


    def _task_count(self):
        conn = self._conn()
        count = conn.execute("SELECT COUNT(*) FROM background_tasks").fetchone()[0]
        conn.close()
        return count

    def _token_usage(self, user_id):
        conn = self._conn()
        usage = conn.execute(
            "SELECT token_usage, token_limit FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        conn.close()
        return tuple(usage)

    def _fail_storage(self, needle):
        real_get_db = app_mod.get_db

        def wrapped():
            conn = real_get_db()
            if getattr(conn, "_doc_limit_wrapped", False):
                return conn
            real_execute = conn.execute

            def execute(sql, params=()):
                statement = sql if isinstance(sql, str) else ""
                if needle in statement:
                    raise sqlite3.OperationalError("injected storage failure")
                return real_execute(sql, params)

            conn.execute = execute
            conn._doc_limit_wrapped = True
            return conn

        app_mod.get_db = wrapped
        return real_get_db

    def test_unavailable_lookup_is_distinct_from_exhaustion(self):
        uid = self._user("classify", token_usage=11, token_limit=500000)
        client = self._client(uid, "user")
        calls = []
        originals = {name: getattr(app_mod, name) for name in _PROVIDER_FUNCS}

        def _fake(name):
            def _inner(*_args, **_kwargs):
                calls.append(name)
                raise RuntimeError("provider_mock_blocked")
            return _inner

        captured = []
        real_thread = threading.Thread

        def _capture(*args, **kwargs):
            thread = real_thread(*args, **kwargs)
            captured.append(thread)
            return thread

        def _join():
            for thread in captured:
                thread.join(timeout=30)
            self.assertFalse(any(thread.is_alive() for thread in captured))

        def _strategy_rows():
            conn = self._conn()
            count = conn.execute(
                "SELECT COUNT(*) FROM strategies WHERE user_id = ?", (uid,)
            ).fetchone()[0]
            conn.close()
            return count

        def _post(path, payload):
            before_tasks = self._task_count()
            before_docs = _strategy_rows()
            before_tokens = self._token_usage(uid)
            response = client.post(path, json=payload, headers=self._headers(self.csrf))
            _join()
            return response, before_tasks, before_docs, before_tokens

        def _assert_quota(response, used, limit):
            self.assertEqual(response.status_code, 429, response.get_data(as_text=True)[:400])
            body = response.get_json()
            self.assertTrue(body.get("limit_reached"))
            self.assertNotIn("limit_check_failed", body)
            if "used" in body:
                self.assertEqual(body["used"], used)
                self.assertEqual(body["limit"], limit)
            self.assertEqual(calls, [])
            self.assertEqual(captured, [])

        def _assert_unavailable_http(response, before_tasks, before_docs, before_tokens):
            self.assertEqual(response.status_code, 503, response.get_data(as_text=True)[:500])
            body = response.get_json()
            self.assertTrue(body.get("limit_check_failed"))
            self.assertFalse(body.get("limit_reached"))
            self.assertNotIn("used", body)
            self.assertNotIn("limit", body)
            text = response.get_data(as_text=True).lower()
            for secret in ("operationalerror", "sqlite", "no such table", "injected", "select "):
                self.assertNotIn(secret, text)
            self.assertEqual(calls, [])
            self.assertEqual(captured, [])
            self.assertEqual(self._task_count(), before_tasks)
            self.assertEqual(_strategy_rows(), before_docs)
            self.assertEqual(self._token_usage(uid), before_tokens)

        for name in _PROVIDER_FUNCS:
            setattr(app_mod, name, _fake(name))
        threading.Thread = _capture
        try:
            admitted = _post("/api/generate-strategy-async", self._strategy_body())
            self.assertEqual(admitted[0].status_code, 200, admitted[0].get_data(as_text=True)[:400])
            self.assertEqual(len(captured), 1)
            self.assertTrue(calls)
            calls.clear()
            captured.clear()
            sync_ok = _post("/api/generate-strategy", self._strategy_body(domain="cybersecurity"))
            self.assertNotEqual(sync_ok[0].status_code, 429, sync_ok[0].get_data(as_text=True)[:400])
            self.assertNotIn("limit_check_failed", sync_ok[0].get_json() or {})
            self.assertTrue(calls)
            calls.clear()
            captured.clear()
            bilingual_ok = _post(
                "/api/generate-bilingual",
                {"type": "strategy", "domain": "الأمن السيبراني", "csrf_token": self.csrf},
            )
            self.assertNotEqual(
                bilingual_ok[0].status_code, 429,
                bilingual_ok[0].get_data(as_text=True)[:400])
            self.assertNotIn("limit_check_failed", bilingual_ok[0].get_json() or {})
            self.assertTrue(calls)
            calls.clear()
            captured.clear()

            self._insert_docs("strategies", uid, 10, "Cyber Security")
            for path, payload in (
                ("/api/generate-strategy-async", self._strategy_body()),
                ("/api/generate-strategy", self._strategy_body(domain="cyber_security")),
                ("/api/generate-bilingual", {
                    "type": "strategy", "domain": "Cyber Security", "csrf_token": self.csrf,
                }),
            ):
                response, *_rest = _post(path, payload)
                _assert_quota(response, 10, 10)

            zero = self._user("zero-route", token_usage=11, token_limit=500000)
            self._override_row(zero, "strategies", "cyber", 0)
            zero_client = self._client(zero, "user")
            zero_response = zero_client.post(
                "/api/generate-strategy-async",
                json=self._strategy_body(),
                headers=self._headers(self.csrf),
            )
            self.assertEqual(zero_response.status_code, 429, zero_response.get_data(as_text=True)[:400])
            zero_body = zero_response.get_json()
            self.assertTrue(zero_body.get("limit_reached"))
            self.assertEqual(zero_body.get("used"), 0)
            self.assertEqual(zero_body.get("limit"), 0)
            self.assertNotIn("limit_check_failed", zero_body)
            self.assertEqual(
                self._remaining(zero, "Cyber Security")["strategies"]["limit_source"],
                "override",
            )
            self.assertEqual(calls, [])
            self.assertEqual(captured, [])

            self._override_row(uid, "strategies", "cyber", -1)
            self._assert_limit_unavailable(uid)
            for path, payload in (
                ("/api/generate-strategy-async", self._strategy_body()),
                ("/api/generate-strategy", self._strategy_body()),
                ("/api/generate-bilingual", {
                    "type": "strategy", "domain": "cybersecurity", "csrf_token": self.csrf,
                }),
            ):
                response, before_tasks, before_docs, before_tokens = _post(path, payload)
                _assert_unavailable_http(response, before_tasks, before_docs, before_tokens)

            conn = self._conn()
            conn.execute("DELETE FROM user_domain_doc_limits WHERE user_id = ?", (uid,))
            conn.commit()
            conn.close()
            real_get_db = self._fail_storage("FROM user_domain_doc_limits")
            try:
                self._assert_limit_unavailable(uid)
                for path, payload in (
                    ("/api/generate-strategy-async", self._strategy_body(domain="الأمن السيبراني")),
                    ("/api/generate-strategy", self._strategy_body()),
                    ("/api/generate-bilingual", {
                        "type": "policy", "domain": "Cyber Security", "csrf_token": self.csrf,
                    }),
                ):
                    response, before_tasks, before_docs, before_tokens = _post(path, payload)
                    _assert_unavailable_http(response, before_tasks, before_docs, before_tokens)
            finally:
                app_mod.get_db = real_get_db

            real_get_db = self._fail_storage("FROM strategies")
            try:
                self._assert_limit_unavailable(uid)
                for path, payload in (
                    ("/api/generate-strategy-async", self._strategy_body()),
                    ("/api/generate-strategy", self._strategy_body(domain="cyber")),
                    ("/api/generate-bilingual", {
                        "type": "strategy", "domain": "Cyber Security", "csrf_token": self.csrf,
                    }),
                ):
                    response, before_tasks, before_docs, before_tokens = _post(path, payload)
                    _assert_unavailable_http(response, before_tasks, before_docs, before_tokens)
            finally:
                app_mod.get_db = real_get_db
        finally:
            threading.Thread = real_thread
            for name, func in originals.items():
                setattr(app_mod, name, func)
            for thread in captured:
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
