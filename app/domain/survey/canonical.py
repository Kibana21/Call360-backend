"""Canonical JSON bytes and SHA-256 fingerprints of survey documents (SS-03A §1.2).

One function produces the bytes of any document, and every hash is taken over those bytes:

* UTF-8; object keys sorted by code point; no insignificant whitespace;
* arrays in their stored order (array order is always meaningful: options, nodes, the survey sequence);
* numbers without exponent and without trailing zeros; a whole value is written as an integer;
* only JSON values: a value of any other type is REFUSED, never converted.

The existing ``app.domain.digest.canonical`` is not reused: it converts unknown types with ``default=str`` and writes
floats in Python's repr, which may use an exponent. Both would break "refuse, never convert" and "no exponent". It is
left untouched for the manifests it already hashes.
"""

from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal
from typing import Any


class CanonicalError(ValueError):
    """The value is not a canonical JSON value (wrong type, non-finite number, non-string key)."""


def _number(v: int | float | Decimal) -> str:
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if not math.isfinite(v):
            raise CanonicalError("a number must be finite")
        d = Decimal(repr(v))  # the shortest decimal that identifies this float: no binary noise, no arithmetic
    else:
        if not v.is_finite():
            raise CanonicalError("a number must be finite")
        d = v
    if d == d.to_integral_value():
        return str(int(d))
    return format(d, "f").rstrip("0").rstrip(".")


def _write(value: Any, out: list[str], path: str) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int | float | Decimal):
        out.append(_number(value))
    elif isinstance(value, str):
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, list | tuple):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _write(item, out, f"{path}[{i}]")
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        for i, key in enumerate(sorted(value)):
            if not isinstance(key, str):
                raise CanonicalError(f"{path}: an object key must be a string")
            if i:
                out.append(",")
            out.append(json.dumps(key, ensure_ascii=False))
            out.append(":")
            _write(value[key], out, f"{path}.{key}")
        out.append("}")
    else:
        raise CanonicalError(f"{path}: {type(value).__name__} is not a JSON value")


def canonical_text(value: Any) -> str:
    out: list[str] = []
    _write(value, out, "$")
    return "".join(out)


def canonical_bytes(value: Any) -> bytes:
    return canonical_text(value).encode("utf-8")


def sha256_hex(value: Any) -> str:
    """The fingerprint of a document: SHA-256 over its canonical bytes, lower-case hexadecimal."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
