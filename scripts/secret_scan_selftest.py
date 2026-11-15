"""Scanner self-test (CP0.1A): proves .gitleaks.toml detects every Call360 secret format and ignores
documented placeholders. Uses only freshly generated synthetic values in a temp dir; prints counts only.

Usage: uv run python scripts/secret_scan_selftest.py [--config .gitleaks.toml] [--samples 50]
"""

from __future__ import annotations

import argparse
import json
import secrets
import shutil
import string
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _rand(n: int) -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


def _pem() -> str:
    from cryptography.hazmat.primitives import serialization as s
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.generate().private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()).decode()


FORMATS: dict[str, tuple[str, Callable[[], str]]] = {
    "postgres_url_app_env": (
        ".env",
        lambda: f"APP_DATABASE_URL=postgresql+psycopg://Call360_db_user:{_rand(16)}@localhost:5432/Call360_db\n",
    ),
    "postgres_url_test_env": (
        ".env",
        lambda: (
            f"TEST_DATABASE_URL=postgresql+psycopg://call360_test_user:{secrets.token_urlsafe(32)}@localhost:5432/Call360_db\n"
        ),
    ),
    # Weak dictionary-style passwords, chosen at runtime so this source file holds no literal credential URL.
    "postgres_url_simple_password": (
        ".env",
        lambda: (
            "DATABASE_URL=postgresql+psycopg://Call360_db_user:"
            f"{secrets.choice(['letmein1', 'changeme', 'qwerty12', 'welcome1'])}@localhost/Call360_db\n"
        ),
    ),
    "postgres_url_in_python": (
        "settings.py",
        lambda: f'URL = "postgres://svc_{_rand(4)}:{_rand(20)}@db.internal:5432/app"\n',
    ),
    "postgres_url_in_typescript": (
        "db.ts",
        lambda: f"const url = 'postgresql://app:{secrets.token_urlsafe(16)}@127.0.0.1/Call360_db';\n",
    ),
    "refresh_token_pepper": (".env", lambda: f"REFRESH_TOKEN_PEPPER={secrets.token_urlsafe(32)}\n"),
    "csrf_secret": (".env", lambda: f"CSRF_SECRET={secrets.token_urlsafe(32)}\n"),
    "dev_account_password": (".env.local", lambda: f"DEV_ADMIN_PASSWORD={secrets.token_urlsafe(18)}\n"),
    "cli_password_env": ("run.sh", lambda: f"export CALL360_NEW_PASSWORD='{secrets.token_urlsafe(14)}'\n"),
    "password_constant": ("config.py", lambda: f'SMTP_PASSWORD = "{_rand(16)}"\n'),
    "jwt_signing_key_pem": ("key.pem", _pem),
}

# Documented placeholders and ordinary code that must NOT fire.
NEGATIVES = {
    ".env.example": (ROOT / ".env.example").read_text(),
    ".env.test.example": (ROOT / ".env.test.example").read_text(),
    "template.py": 'f"TEST_DATABASE_URL=postgresql+psycopg://{TEST_ROLE}:{password}@localhost:5432/Call360_db"\n'
    'URL = "postgresql+psycopg://${DB_USER}:${DB_PASSWORD}@localhost/Call360_db"\n'
    'PASSWORD = "Correct-Horse-Battery-9"\nCSRF_COOKIE = "c360_csrf"\nACCESS_TOKEN_TTL_SECONDS = 600\n'
    'password = hash_password(password)\nnoauth = "postgresql+psycopg://openapi@localhost/Call360_db"\n',
    "client.ts": "export const CSRF_COOKIE = 'c360_csrf';\nconst LOCK_NAME = 'c360-refresh';\n",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(ROOT / ".gitleaks.toml"))
    parser.add_argument("--samples", type=int, default=50)
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="c360-scan-selftest-"))
    try:
        for name, (filename, make) in FORMATS.items():
            for i in range(args.samples):
                target = work / "positive" / name / str(i) / filename
                target.parent.mkdir(parents=True)
                target.write_text(make())
        for filename, text in NEGATIVES.items():
            target = work / "negative" / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        report = work / "report.json"
        gitleaks = shutil.which("gitleaks")
        if gitleaks is None:
            print("BLOCKED: gitleaks not installed")
            return 2
        subprocess.run(  # noqa: S603 — fixed argv, no shell, absolute binary path
            [
                gitleaks,
                "dir",
                str(work),
                "--config",
                args.config,
                "--no-banner",
                "--redact",
                "--report-format",
                "json",
                "--report-path",
                str(report),
            ],
            capture_output=True,
            check=False,
        )
        findings = json.loads(report.read_text() or "[]")
        hits: dict[str, set[str]] = {}
        false_positives: list[str] = []
        for f in findings:
            rel = Path(f["File"]).relative_to(work).parts
            if rel[0] == "negative":
                false_positives.append(f"{rel[1]} ({f['RuleID']})")
            else:
                hits.setdefault(rel[1], set()).add(rel[2])
        ok = True
        for name in FORMATS:
            n = len(hits.get(name, set()))
            ok &= n == args.samples
            print(f"{'PASS' if n == args.samples else 'FAIL'}  {name:30} {n}/{args.samples}")
        print(
            f"{'PASS' if not false_positives else 'FAIL'}  placeholders/ordinary code          "
            f"{len(false_positives)} false positives {sorted(set(false_positives))}"
        )
        return 0 if ok and not false_positives else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
