"""Engine and session factory bound to exactly one configured schema."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.settings import Settings


def make_engine(settings: Settings) -> Engine:
    schema = settings.target_schema
    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        hide_parameters=True,
        connect_args={"options": f"-c search_path={schema}"},
    )
    return engine.execution_options(schema_translate_map={None: schema})


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)
