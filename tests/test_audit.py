"""BE-AUD-01, BE-AUD-02 — append-only audit trail and hash-chain verification."""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.audit.chain import Actor, RequestMeta, verify_chain, write_audit
from app.db.session import make_session_factory


def _one_event(db: Session) -> None:
    write_audit(db, action="TEST.EVENT", outcome="SUCCEEDED", actor=Actor(service="pytest"), meta=RequestMeta())
    db.commit()


@pytest.mark.parametrize(
    "stmt",
    [
        "UPDATE audit_event SET reason = 'tampered'",
        "DELETE FROM audit_event",
        "TRUNCATE audit_event",
    ],
)
def test_be_aud_01_audit_rows_cannot_be_changed(db: Session, stmt: str) -> None:
    _one_event(db)
    with pytest.raises(DBAPIError, match="append-only"):
        db.execute(text(stmt))
    db.rollback()


def test_be_aud_02_chain_verifies_and_detects_tamper(db: Session, engine: Engine) -> None:
    _one_event(db)
    _one_event(db)
    report = verify_chain(db)
    assert report.ok and report.events >= 2 and report.head
    # Simulate a privileged tamper (table owner disables the trigger) inside a transaction we roll back.
    with make_session_factory(engine)() as s:
        s.execute(text("ALTER TABLE audit_event DISABLE TRIGGER audit_event_no_update_delete"))
        s.execute(
            text(
                "UPDATE audit_event SET reason = 'tampered' "
                "WHERE seq = (SELECT min(seq) FROM audit_event WHERE action = 'TEST.EVENT')"
            )
        )
        broken = verify_chain(s)
        assert not broken.ok and broken.first_break_seq is not None
        s.rollback()
    assert verify_chain(db).ok
