"""Canonical survey documents: kinds, structural contracts, the bundle a survey is validated in, and its manifest
(SS-03A §1, §3). Shapes are those of the contract (04 §1–§8); snake_case throughout.

A document is a plain JSON object. ``check_document`` verifies its STRUCTURE only (fields, types, allowed values) and
reports stable codes; meaning is the validator's job (``validator.validate``).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from app.domain.survey.canonical import sha256_hex

Doc = Mapping[str, Any]

KINDS = ("OPTION_SET", "ITEM", "WORDING", "CONDITION", "MODULE", "SURVEY")
SCHEMA_OF = {
    "OPTION_SET": "call360.survey.option-set/1",
    "ITEM": "call360.survey.item/1",
    "WORDING": "call360.survey.wording/1",
    "CONDITION": "call360.survey.condition/1",
    "MODULE": "call360.survey.module/1",
    "SURVEY": "call360.survey.content/1",
}

ANSWER_TYPES = ("YES_NO", "SINGLE_SELECT", "MULTI_SELECT", "FREE_TEXT", "NUMERIC", "ACKNOWLEDGEMENT", "STATEMENT")
#: Items with no enumerated answers: exactly one route out of their own node (owner decision TS-2, as amended — this
#: restricts the item node only, never a Decision node placed after it).
SINGLE_ROUTE_TYPES = ("FREE_TEXT", "NUMERIC", "ACKNOWLEDGEMENT", "STATEMENT")
STATEMENT_ROLES = ("OPENING", "TRANSITION", "DISCLOSURE", "CLOSING")
LIFECYCLE_ROLES = ("IDENTITY_CHECK", "CONSENT_TO_PROCEED", "RECORDING_CONSENT", "CLOUD_PROCESSING_CONSENT")
DELIVERY_MODES = ("CONTROLLED_TTS", "EXACT_AUDIO", "CONVERSATIONAL")
#: The only delivery modes a candidate may contain (owner decision TS-4, as amended).
PUBLISHABLE_DELIVERY_MODES = ("CONTROLLED_TTS", "EXACT_AUDIO")
ROUTING_MODES = ("ALL_TO_NEXT", "PER_CHOICE", "SEQUENTIAL_FOLLOWUPS", "ORDERED_RULES")
NODE_TYPES = ("QUESTION", "STATEMENT", "DECISION")
UNKNOWN_POLICIES = ("BLOCK", "SKIP_WITH_REASON", "ROUTE")
INTERRUPT_CLASSES = ("OPTIONAL", "MANDATORY")
INTERRUPT_POLICIES = ("STOP_ESCALATE", "RESUME", "STOP_REJOIN")
FIELD_TYPES = ("MONEY", "INTEGER", "ENUM", "BOOLEAN", "TEXT")
#: Outcome classes fixed by the schema. NON_ANSWER_EXCEPTION is a category only: no outcome of that class exists and
#: no non-answer behaviour is approved (owner decisions D-179, D-180).
OUTCOME_CLASSES = ("NORMAL_COMPLETION", "EXCEPTION", "ESCALATION", "REVIEW_HALT", "NON_ANSWER_EXCEPTION")


@dataclass(frozen=True)
class DocumentProblem:
    code: str
    path: str
    detail: str = ""


Check = Callable[[Any], bool]
_str: Check = lambda v: isinstance(v, str) and v != ""  # noqa: E731
_text: Check = lambda v: isinstance(v, str)  # noqa: E731
_int: Check = lambda v: isinstance(v, int) and not isinstance(v, bool)  # noqa: E731
_posint: Check = lambda v: isinstance(v, int) and not isinstance(v, bool) and v >= 1  # noqa: E731
_bool: Check = lambda v: isinstance(v, bool)  # noqa: E731
_obj: Check = lambda v: isinstance(v, dict)  # noqa: E731
_arr: Check = lambda v: isinstance(v, list)  # noqa: E731
_num: Check = lambda v: isinstance(v, int | float) and not isinstance(v, bool)  # noqa: E731


def _one_of(*allowed: str) -> Check:
    return lambda v: v in allowed


def _ref(v: Any) -> bool:
    return isinstance(v, dict) and _str(v.get("code")) and _posint(v.get("version"))


#: kind -> (required fields, optional fields); each field has one structural check.
#: ``authoring`` (FI-1, optional, on ITEM, MODULE and CONDITION): notes an editor keeps with the document — a module's
#: stated intent and recommended entry rule, a condition's parameter labels, the wording version of an unplaced item.
#: It is part of the document and of its hash, and it has NO execution meaning: no validator rule, condition or route
#: reads it. A document without it is unchanged.
_CONTRACT: dict[str, tuple[dict[str, Check], dict[str, Check]]] = {
    "OPTION_SET": ({"schema": _str, "code": _str, "version": _posint, "options": _arr}, {}),
    "ITEM": (
        {"schema": _str, "code": _str, "version": _posint, "answer_type": _one_of(*ANSWER_TYPES), "intent": _text},
        {
            "option_set": _ref,
            "selection": _obj,
            "text_rule": _obj,
            "number_rule": _obj,
            "statement_role": _one_of(*STATEMENT_ROLES),
            "lifecycle_role": _one_of(*LIFECYCLE_ROLES),
            # a code of the governed catalog; its classes and meaning await D-NA-5 / D-NA-10 and are not approved
            "response_obligation": _str,
            "authoring": _obj,
        },
    ),
    "WORDING": (
        {
            "schema": _str,
            "item": _str,
            "language": _one_of("en"),  # single language initially (owner decision AD-12)
            "wording_version": _posint,
            "text": _text,
            "delivery_mode": _one_of(*DELIVERY_MODES),  # always explicit in storage (TS-4)
        },
        {"asset": _obj, "option_texts": _obj},
    ),
    "CONDITION": (
        {"schema": _str, "code": _str, "version": _posint, "name": _text, "ast": _obj},
        {"params": _obj, "inputs": _obj, "authoring": _obj},
    ),
    "MODULE": (
        {
            "schema": _str,
            "code": _str,
            "revision": _posint,
            "name": _text,
            "outcomes": _arr,
            "nodes": _arr,
            "edges": _arr,
        },
        {"entry": lambda v: v is None or _str(v), "kind": _str, "authoring": _obj},
    ),
    "SURVEY": ({"schema": _str, "code": _str, "sequence": _arr}, {}),
}


def check_document(kind: str, doc: Any) -> list[DocumentProblem]:
    """Structural problems of one document. Empty = it has the shape of its kind."""
    if kind not in _CONTRACT:
        return [DocumentProblem("DOCUMENT_KIND_UNKNOWN", "$", kind)]
    if not isinstance(doc, dict):
        return [DocumentProblem("DOCUMENT_NOT_AN_OBJECT", "$")]
    out: list[DocumentProblem] = []
    required, optional = _CONTRACT[kind]
    if doc.get("schema") != SCHEMA_OF[kind]:
        # a reader refuses a schema it does not know: it never guesses at a newer or older shape
        out.append(DocumentProblem("DOCUMENT_SCHEMA_UNKNOWN", "$.schema", str(doc.get("schema"))))
    for name, check in required.items():
        if name not in doc:
            out.append(DocumentProblem("DOCUMENT_FIELD_MISSING", f"$.{name}"))
        elif not check(doc[name]):
            out.append(DocumentProblem("DOCUMENT_FIELD_INVALID", f"$.{name}"))
    for name in doc:
        if name in required:
            continue
        if name not in optional:
            out.append(DocumentProblem("DOCUMENT_FIELD_UNKNOWN", f"$.{name}"))
        elif not optional[name](doc[name]):
            out.append(DocumentProblem("DOCUMENT_FIELD_INVALID", f"$.{name}"))
    if out:
        return out
    out.extend(_deep(kind, doc))
    return out


def _deep(kind: str, doc: Doc) -> list[DocumentProblem]:
    out: list[DocumentProblem] = []

    def bad(path: str, detail: str = "") -> None:
        out.append(DocumentProblem("DOCUMENT_FIELD_INVALID", path, detail))

    if kind == "OPTION_SET":
        seen: set[str] = set()
        for i, o in enumerate(doc["options"]):
            if not isinstance(o, dict) or not _str(o.get("code")) or not _text(o.get("label", "")):
                bad(f"$.options[{i}]")
                continue
            if o["code"] in seen:
                out.append(DocumentProblem("DOCUMENT_DUPLICATE_CODE", f"$.options[{i}].code", o["code"]))
            seen.add(o["code"])
            if "interrupt" in o and o["interrupt"] not in INTERRUPT_CLASSES:
                bad(f"$.options[{i}].interrupt")
    elif kind == "MODULE":
        ids: set[str] = set()
        for i, n in enumerate(doc["nodes"]):
            if not isinstance(n, dict) or not _str(n.get("node")) or n.get("type") not in NODE_TYPES:
                bad(f"$.nodes[{i}]")
                continue
            if n["node"] in ids:
                out.append(DocumentProblem("DOCUMENT_DUPLICATE_CODE", f"$.nodes[{i}].node", n["node"]))
            ids.add(n["node"])
            if n["type"] == "DECISION":
                if "binding" in n and n["binding"] is not None and not isinstance(n["binding"], dict):
                    bad(f"$.nodes[{i}].binding")
            else:
                item = n.get("item")
                if not (isinstance(item, dict) and _ref(item) and _posint(item.get("wording_version"))):
                    bad(f"$.nodes[{i}].item")
                if not isinstance(n.get("routing"), dict) or n["routing"].get("mode") not in ROUTING_MODES:
                    bad(f"$.nodes[{i}].routing")
        edges: set[str] = set()
        for i, e in enumerate(doc["edges"]):
            ok = (
                isinstance(e, dict)
                and _str(e.get("edge"))
                and _str(e.get("from"))
                and _str(e.get("on"))
                and isinstance(e.get("to"), dict)
            )
            if not ok:
                bad(f"$.edges[{i}]")
                continue
            if e["edge"] in edges:
                out.append(DocumentProblem("DOCUMENT_DUPLICATE_CODE", f"$.edges[{i}].edge", e["edge"]))
            edges.add(e["edge"])
        if any(not _str(o) for o in doc["outcomes"]):
            bad("$.outcomes")
    elif kind == "SURVEY":
        names: set[str] = set()
        for i, inst in enumerate(doc["sequence"]):
            mod = inst.get("module") if isinstance(inst, dict) else None
            ok = (
                isinstance(inst, dict)
                and _str(inst.get("instance"))
                and isinstance(mod, dict)
                and _str(mod.get("code"))
                and _posint(mod.get("revision"))
            )
            if not ok or not isinstance(inst.get("routes"), dict):
                bad(f"$.sequence[{i}]")
                continue
            if inst["instance"] in names:
                out.append(DocumentProblem("DOCUMENT_DUPLICATE_CODE", f"$.sequence[{i}].instance", inst["instance"]))
            names.add(inst["instance"])
    return out


# ---------------------------------------------------------------------------------------------------------- the bundle
@dataclass(frozen=True)
class Bundle:
    """Everything a survey content pins, resolved: what the validator and the manifest work on."""

    fields: Mapping[str, Doc]  # the governed field catalog: code -> {type, unit?, values?, speakable?}
    outcomes: Mapping[str, str]  # the governed outcome catalog: code -> class
    option_sets: Mapping[tuple[Any, Any], Doc]
    items: Mapping[tuple[Any, Any], Doc]
    wordings: Mapping[tuple[Any, Any], Doc]  # (item code, wording_version); single language
    conditions: Mapping[tuple[Any, Any], Doc]
    modules: Mapping[tuple[Any, Any], Doc]
    survey: Doc
    #: codes of the governed response-obligation catalog; None = membership is not checked
    obligations: frozenset[str] | None = None

    @staticmethod
    def build(
        *,
        fields: Mapping[str, Doc],
        outcomes: Mapping[str, str],
        option_sets: Iterable[Doc] = (),
        items: Iterable[Doc] = (),
        wordings: Iterable[Doc] = (),
        conditions: Iterable[Doc] = (),
        modules: Iterable[Doc] = (),
        survey: Doc,
        obligations: Iterable[str] | None = None,
    ) -> Bundle:
        return Bundle(
            fields=dict(fields),
            outcomes=dict(outcomes),
            option_sets={(d["code"], d["version"]): d for d in option_sets},
            items={(d["code"], d["version"]): d for d in items},
            wordings={(d["item"], d["wording_version"]): d for d in wordings},
            conditions={(d["code"], d["version"]): d for d in conditions},
            modules={(d["code"], d["revision"]): d for d in modules},
            survey=survey,
            obligations=None if obligations is None else frozenset(obligations),
        )

    def module_of(self, instance: Doc) -> Doc | None:
        m = instance.get("module") or {}
        return self.modules.get((m.get("code"), m.get("revision")))

    def item_of(self, node: Doc) -> Doc | None:
        i = node.get("item") or {}
        return self.items.get((i.get("code"), i.get("version")))

    def wording_of(self, node: Doc) -> Doc | None:
        i = node.get("item") or {}
        return self.wordings.get((i.get("code"), i.get("wording_version")))

    def options_of(self, item: Doc) -> list[Doc]:
        ref = item.get("option_set")
        s = self.option_sets.get((ref["code"], ref["version"])) if ref else None
        return list(s["options"]) if s else []

    def condition_of(self, binding: Doc | None) -> Doc | None:
        c = (binding or {}).get("condition") or {}
        return self.conditions.get((c.get("code"), c.get("version")))


# -------------------------------------------------------------------------------------------------------- the manifest
def manifest_of(bundle: Bundle) -> list[dict[str, Any]]:
    """Every asset version the survey content pins, directly or through a module: ``{kind, code, version, sha256}``,
    sorted by kind, code, version. A reference that does not resolve is absent here; the validator reports it."""
    entries: dict[tuple[str, str, int], str] = {}

    def add(kind: str, code: str, version: int, doc: Doc | None) -> None:
        if doc is not None:
            entries[(kind, code, version)] = sha256_hex(doc)

    def add_condition(binding: Doc | None) -> None:
        c = (binding or {}).get("condition") or {}
        if c.get("code"):
            add("CONDITION", c["code"], c.get("version", 0), bundle.conditions.get((c["code"], c.get("version"))))

    for inst in bundle.survey.get("sequence", []):
        add_condition(inst.get("eligibility"))
        m = bundle.module_of(inst)
        if m is None:
            continue
        add("MODULE", m["code"], m["revision"], m)
        for n in m["nodes"]:
            if n["type"] == "DECISION":
                add_condition(n.get("binding"))
                continue
            ref = n["item"]
            item = bundle.item_of(n)
            add("ITEM", ref["code"], ref["version"], item)
            add("WORDING", ref["code"], ref["wording_version"], bundle.wording_of(n))
            if item and item.get("option_set"):
                os_ref = item["option_set"]
                add(
                    "OPTION_SET",
                    os_ref["code"],
                    os_ref["version"],
                    bundle.option_sets.get((os_ref["code"], os_ref["version"])),
                )
    return [{"kind": k, "code": c, "version": v, "sha256": h} for (k, c, v), h in sorted(entries.items())]


def manifest_sha256(manifest: list[dict[str, Any]]) -> str:
    return sha256_hex(manifest)
