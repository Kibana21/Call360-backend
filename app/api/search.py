"""Global search and suggestions (F2: API-070, API-071; SEARCH-001/003/006/007).

Matching runs only over rows already restricted to the caller's markets, so hits, counts and suggestions never
reveal an out-of-scope record. Phone and email are exact matches on the protected HMAC token. Search terms are
logged and audited only as a normalised SHA-256 (S-14, BE-SRCH-08).
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.api.cases import scoped
from app.api.schemas import ErrorResponse, PageInfo, SearchHit, SearchResults, SearchSuggestions
from app.audit.chain import write_audit
from app.core.errors import AppError
from app.domain.register import MAX_Q, TYPE_ORDER, InvalidFilter, search_cursor, search_hits, search_offset, term_hash
from app.security.authz import AuthContext, get_db, request_meta, require

router = APIRouter(prefix="/api/v1/search", tags=["search"])
_ERR: dict[int | str, dict[str, Any]] = {code: {"model": ErrorResponse} for code in (401, 403, 422, 429)}
log = logging.getLogger("call360.search")


def _query(q: str) -> str:
    if len(q) > MAX_Q:
        raise AppError(422, "QUERY_TOO_LONG", f"q must be at most {MAX_Q} characters")
    if not q.strip():
        raise AppError(422, "VALIDATION_FAILED", "q must not be blank")
    return q


def _types(types: list[str]) -> set[str]:
    bad = [t for t in types if t not in TYPE_ORDER]
    if bad:
        raise AppError(422, "INVALID_FILTER", f"Unknown type: {bad[0]}")
    return set(types) or set(TYPE_ORDER)


@router.get("", response_model=SearchResults, operation_id="search", responses=_ERR)
def search(
    request: Request,
    q: str = Query(..., description=f"1–{MAX_Q} characters"),
    types: list[str] = Query([], description="case | policy | attempt | session"),
    limit: int = Query(20, ge=1, le=50),
    cursor: str | None = Query(None, max_length=512),
    auth: AuthContext = Depends(require("search.use")),
    db: Session = Depends(get_db),
) -> SearchResults:
    q = _query(q)
    wanted = _types(types)
    qh = term_hash(q)
    _, rows = scoped(db, auth)
    hits = search_hits(rows, q, request.app.state.data_protection, wanted)
    try:
        offset = search_offset(cursor, qh)
    except InvalidFilter as exc:
        raise AppError(422, exc.code, str(exc)) from exc
    chunk = hits[offset : offset + limit]
    nxt = search_cursor(offset + limit, qh) if offset + limit < len(hits) else None
    write_audit(
        db,
        action="SEARCH.EXECUTED",
        outcome="SUCCEEDED",
        actor=auth.actor,
        meta=request_meta(request),
        entity_type="search",
        reason="Global search (term recorded only as SHA-256)",
        after={"q_sha256": qh, "types": sorted(wanted), "hits": len(hits), "markets": sorted(auth.markets)},
    )
    db.commit()
    log.info("global search", extra={"q_sha256": qh, "hits": len(hits), "cid": request.state.correlation_id})
    return SearchResults(
        items=[SearchHit(**h) for h in chunk],
        total=len(hits),
        counts=dict(Counter(h["entity_type"] for h in hits)),
        page=PageInfo(next_cursor=nxt, limit=limit, sort="rank"),
        markets=sorted(auth.markets),
    )


@router.get("/suggest", response_model=SearchSuggestions, operation_id="search_suggest", responses=_ERR)
def suggest(
    request: Request,
    q: str = Query(..., description=f"1–{MAX_Q} characters"),
    auth: AuthContext = Depends(require("search.use")),
    db: Session = Depends(get_db),
) -> SearchSuggestions:
    q = _query(q)
    _, rows = scoped(db, auth)
    hits = search_hits(rows, q, request.app.state.data_protection, set(TYPE_ORDER))[:8]
    log.info("search suggest", extra={"q_sha256": term_hash(q), "cid": request.state.correlation_id})
    return SearchSuggestions(items=[SearchHit(**h) for h in hits], markets=sorted(auth.markets))
