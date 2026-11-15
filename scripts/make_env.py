"""Create the gitignored development ``.env`` (D-16/D-22). Secrets are generated locally and never printed.

Usage: uv run python scripts/make_env.py   (prompts for the Call360_db_user password without echo)
"""

from __future__ import annotations

import getpass
import os
import secrets
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    target = ROOT / ".env"
    if target.exists() and "--force" not in sys.argv:
        print(".env already exists; leaving it unchanged (use --force to regenerate).")
        return 0
    password = os.environ.pop("CALL360_DB_PASSWORD", None) or getpass.getpass("Password for Call360_db_user: ")
    url = f"postgresql+psycopg://Call360_db_user:{quote(password, safe='')}@localhost:5432/Call360_db"
    target.write_text(
        "APP_ENV=local\nDATA_POLICY=SYNTHETIC_ONLY\n"
        f"APP_DATABASE_URL={url}\nAPP_DB_SCHEMA=call360\n"
        "EXPECTED_DATABASE=Call360_db\nEXPECTED_DB_ROLE=Call360_db_user\nAPP_DB_ROLE=Call360_db_user\n"
        "JWT_PRIVATE_KEY_PATH=.secrets/jwt_ed25519_private.pem\nJWT_PUBLIC_KEY_PATH=.secrets/jwt_ed25519_public.pem\n"
        f"REFRESH_TOKEN_PEPPER={secrets.token_urlsafe(32)}\nCSRF_SECRET={secrets.token_urlsafe(32)}\n"
        'ALLOWED_ORIGINS=["http://localhost:5173","http://127.0.0.1:5173"]\nCOOKIE_SECURE=false\n'
    )
    target.chmod(0o600)
    print("Wrote .env (gitignored, mode 600).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
