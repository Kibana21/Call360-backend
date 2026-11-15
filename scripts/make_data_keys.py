"""Add the two CP0.2 data-protection keys (D-34) to a gitignored env file. Keys are never printed.

Usage: uv run python scripts/make_data_keys.py --env-file .env.test
       uv run python scripts/make_data_keys.py --env-file .env --allow-development   (needs owner approval)

Existing keys are kept unchanged, so ciphertext and HMAC tokens stay readable and seed digests stay
comparable between runs (D-33). Rotation is out of scope for S0 (RR-02).
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("PII_ENCRYPTION_KEY", "PII_HMAC_KEY")


def _key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--allow-development", action="store_true")
    args = parser.parse_args()
    target = (ROOT / args.env_file).resolve()
    if target.parent != ROOT or not target.name.startswith(".env") or target.name.endswith(".example"):
        print("Refusing: target must be a gitignored .env* file in the backend root.")
        return 2
    if target.name == ".env" and not args.allow_development:
        print("Refusing: the development .env needs --allow-development (owner-approved deployment only).")
        return 2
    if not target.exists():
        print(f"Refusing: {target.name} does not exist.")
        return 2
    lines = target.read_text().splitlines()
    present = {n for n in NAMES if any(line.startswith(f"{n}=") for line in lines)}
    if present == set(NAMES):
        print(f"{target.name}: data-protection keys already present; left unchanged.")
        return 0
    if present:
        print(f"Refusing: {target.name} has only {sorted(present)}; fix the file by hand.")
        return 2
    with target.open("a") as fh:
        if lines and lines[-1] != "":
            fh.write("\n")
        for name in NAMES:
            fh.write(f"{name}={_key()}\n")
    target.chmod(0o600)
    print(f"{target.name}: added {', '.join(NAMES)} (values not shown; file mode 600).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
