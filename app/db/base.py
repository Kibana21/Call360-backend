"""Declarative base. Models are schema-less; the configured schema is applied through
``schema_translate_map`` and ``search_path`` on every connection (D-22)."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
