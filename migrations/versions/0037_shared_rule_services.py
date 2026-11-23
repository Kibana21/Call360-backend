"""SHARED-1 — Assignment Rules and Finding Rules stand on their own. Two columns, five guards, eight permissions.

Until now a published assignment rule had no market of its own: its market was its target script family's, and a rule
could not exist without a published script to target. Survey assignment binds surveys to these same rules, so no new
rule could be written — for surveys either — without Script Studio publishing a script first.

* ``script_assignment_rule_version.market_code`` — the rule's OWN governed market. Back-filled for every existing rule
  from its target script family (the authoritative source until now) and verified row by row before the migration
  commits. Immutable with the rest of a published version.
* ``target_kind`` on the rule version and on the draft — ``SCRIPT_VERSION`` (the default: every existing rule) or
  ``SURVEY_BINDING``. A ``SURVEY_BINDING`` rule names no script and selects a survey only through a governed survey
  binding. ``CHECK ((target_kind = 'SCRIPT_VERSION') = (target_script_version_id IS NOT NULL))``.
* Guards: a script-backed rule and its target script belong to the same market; the kind of a draft never changes; a
  ``script_assignment`` can never be matched by a rule that is not script-backed; a survey binding, its rule and its
  survey belong to the same market; a requirement-group member is a rule of the group's market.
* Permissions ``assignment_rule.{read,edit,approve,publish}`` and ``finding_rule.{read,edit,approve,publish}`` are
  created and granted to NO role. The existing ``script.*`` permissions keep working for both capabilities.

PRESERVED: every rule's identity, version, predicate, priority, target, checksum, author and checker; publication rows
and change events; every survey binding, group, plan and evaluation; every operational record. The only data written
is ``market_code`` on existing rule versions. The whole migration is one transaction: a failed verification leaves the
schema exactly as it was.

Revision ID: 0037_shared_rule_services
Revises: 0036_survey_module_authoring
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op

from app.db.ddl import market_trigger

revision = "0037_shared_rule_services"
down_revision = "0036_survey_module_authoring"
branch_labels = None
depends_on = None

PERMISSIONS = {
    "assignment_rule.read": "Read assignment rules, their drafts, history and explanations (SHARED-1)",
    "assignment_rule.edit": "Create and edit assignment rule drafts and submit them for review (SHARED-1)",
    "assignment_rule.approve": "Approve or return a submitted assignment rule; never one you made (SHARED-1)",
    "assignment_rule.publish": "Publish an approved assignment rule; never one you made (SHARED-1)",
    "finding_rule.read": "Read finding rule sets and their history (SHARED-1)",
    "finding_rule.edit": "Create and edit finding rule set drafts and submit them for review (SHARED-1)",
    "finding_rule.approve": "Approve or return a submitted finding rule set; never one you made (SHARED-1)",
    "finding_rule.publish": "Publish an approved finding rule set; never one you made (SHARED-1)",
}
KINDS = "('SCRIPT_VERSION', 'SURVEY_BINDING')"
#: every pre-existing column of every rule version, as one digest: what the back-fill must not change
RULE_DIGEST = (
    "SELECT count(*), coalesce(md5(string_agg(md5((to_jsonb(r) - 'market_code' - 'target_kind')::text), '' "
    "ORDER BY r.id)), '') FROM {s}.script_assignment_rule_version r"
)


def upgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    before = tuple(conn.execute(sa.text(RULE_DIGEST.format(s=s))).one())

    # ---- 1. the columns
    op.execute(
        f"ALTER TABLE {s}.script_assignment_rule_version ADD COLUMN market_code varchar(40), "
        f"ADD COLUMN target_kind varchar(16) NOT NULL DEFAULT 'SCRIPT_VERSION'"
    )
    op.execute(
        f"ALTER TABLE {s}.assignment_rule_draft ADD COLUMN target_kind varchar(16) NOT NULL DEFAULT 'SCRIPT_VERSION'"
    )

    # ---- 2. back-fill the market of every existing rule from its target script family. A published rule version is
    # immutable (trigger); the guard is lifted for exactly this statement and restored in the same transaction.
    op.execute(f"ALTER TABLE {s}.script_assignment_rule_version DISABLE TRIGGER assignment_rule_version_guard")
    op.execute(
        f"UPDATE {s}.script_assignment_rule_version r SET market_code = f.market_code FROM {s}.script_version v "
        f"JOIN {s}.script_family f ON f.id = v.script_family_id WHERE v.id = r.target_script_version_id"
    )
    op.execute(f"ALTER TABLE {s}.script_assignment_rule_version ENABLE TRIGGER assignment_rule_version_guard")

    # ---- 3. verify before anything depends on it
    missing = conn.execute(
        sa.text(f"SELECT count(*) FROM {s}.script_assignment_rule_version WHERE market_code IS NULL")
    ).scalar_one()
    wrong = conn.execute(
        sa.text(
            f"SELECT count(*) FROM {s}.script_assignment_rule_version r JOIN {s}.script_version v "
            f"ON v.id = r.target_script_version_id JOIN {s}.script_family f ON f.id = v.script_family_id "
            "WHERE r.market_code IS DISTINCT FROM f.market_code"
        )
    ).scalar_one()
    after = tuple(conn.execute(sa.text(RULE_DIGEST.format(s=s))).one())
    if missing or wrong or after != before:
        raise RuntimeError(
            f"assignment rule market back-fill failed verification: {missing} without a market, {wrong} differing "
            f"from their script family, rules before/after {before[0]}/{after[0]}, "
            f"content unchanged: {after == before}"
        )
    for table, rule in (("survey_assignment_binding", "b"), ("survey_assignment_group", "g")):
        bad = conn.execute(
            sa.text(
                f"SELECT count(*) FROM {s}.survey_assignment_binding b JOIN {s}.script_assignment_rule_version r "
                "ON r.id = b.rule_version_id WHERE b.market_code <> r.market_code"
                if rule == "b"
                else f"SELECT count(*) FROM {s}.survey_assignment_group_member m JOIN {s}.survey_assignment_group g "
                f"ON g.id = m.group_id JOIN {s}.script_assignment_rule_version r ON r.id = m.rule_version_id "
                "WHERE g.market_code <> r.market_code"
            )
        ).scalar_one()
        if bad:
            raise RuntimeError(f"{bad} existing rows of {table} are not in their rule's market")

    # ---- 4. constraints
    op.execute(f"ALTER TABLE {s}.script_assignment_rule_version ALTER COLUMN market_code SET NOT NULL")
    op.execute(market_trigger(s, "script_assignment_rule_version"))
    op.execute(f"ALTER TABLE {s}.script_assignment_rule_version ALTER COLUMN target_script_version_id DROP NOT NULL")
    op.execute(
        f"ALTER TABLE {s}.script_assignment_rule_version ADD CONSTRAINT ck_assignment_rule_target_kind CHECK "
        f"(target_kind IN {KINDS} AND (target_kind = 'SCRIPT_VERSION') = (target_script_version_id IS NOT NULL))"
    )
    op.execute(
        f"ALTER TABLE {s}.assignment_rule_draft ADD CONSTRAINT ck_assignment_rule_draft_target_kind CHECK "
        f"(target_kind IN {KINDS} AND (target_kind = 'SCRIPT_VERSION' OR target_script_version_id IS NULL))"
    )
    op.execute(f"ALTER TABLE {s}.assignment_rule_draft DROP CONSTRAINT ck_assignment_rule_draft_frozen")
    op.execute(
        f"ALTER TABLE {s}.assignment_rule_draft ADD CONSTRAINT ck_assignment_rule_draft_frozen CHECK ("
        "status IN ('DRAFT', 'ABANDONED') OR (manifest IS NOT NULL AND manifest_sha256 IS NOT NULL "
        "AND (target_kind = 'SURVEY_BINDING' OR target_script_version_id IS NOT NULL)))"
    )

    # ---- 5. guards
    op.execute(f"""
        CREATE FUNCTION {s}.assignment_rule_market_check() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          -- a script-backed rule written without a market (the seed, or code that predates this migration) takes its
          -- script family's: the source that was authoritative until now. A rule that names no script must state one.
          IF NEW.market_code IS NULL AND NEW.target_script_version_id IS NOT NULL THEN
            SELECT f.market_code INTO NEW.market_code FROM {s}.script_version v
              JOIN {s}.script_family f ON f.id = v.script_family_id WHERE v.id = NEW.target_script_version_id;
          END IF;
          IF NEW.target_script_version_id IS NOT NULL AND NOT EXISTS (
              SELECT 1 FROM {s}.script_version v JOIN {s}.script_family f ON f.id = v.script_family_id
               WHERE v.id = NEW.target_script_version_id AND f.market_code = NEW.market_code) THEN
            RAISE EXCEPTION 'an assignment rule and its target script belong to the same market'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER assignment_rule_market_check BEFORE INSERT ON {s}.script_assignment_rule_version
          FOR EACH ROW EXECUTE FUNCTION {s}.assignment_rule_market_check();

        CREATE FUNCTION {s}.assignment_rule_draft_kind_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.target_kind IS DISTINCT FROM OLD.target_kind THEN
            RAISE EXCEPTION 'what an assignment rule selects is fixed when it is created'
              USING ERRCODE = 'insufficient_privilege';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER assignment_rule_draft_kind_guard BEFORE UPDATE ON {s}.assignment_rule_draft
          FOR EACH ROW EXECUTE FUNCTION {s}.assignment_rule_draft_kind_guard();

        CREATE FUNCTION {s}.script_assignment_rule_kind_check() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.matched_rule_version_id IS NOT NULL AND EXISTS (
              SELECT 1 FROM {s}.script_assignment_rule_version r
               WHERE r.id = NEW.matched_rule_version_id AND r.target_kind <> 'SCRIPT_VERSION') THEN
            RAISE EXCEPTION 'a survey-only assignment rule can never assign a script to a case'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER script_assignment_rule_kind_check BEFORE INSERT ON {s}.script_assignment
          FOR EACH ROW EXECUTE FUNCTION {s}.script_assignment_rule_kind_check();

        CREATE FUNCTION {s}.survey_binding_market_check() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM {s}.script_assignment_rule_version r
                          WHERE r.id = NEW.rule_version_id AND r.market_code = NEW.market_code)
             OR NOT EXISTS (SELECT 1 FROM {s}.survey_definition d
                             WHERE d.id = NEW.survey_definition_id AND d.market_code = NEW.market_code) THEN
            RAISE EXCEPTION 'a survey binding, its rule and its survey belong to the same market'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER survey_binding_market_check BEFORE INSERT ON {s}.survey_assignment_binding
          FOR EACH ROW EXECUTE FUNCTION {s}.survey_binding_market_check();

        CREATE FUNCTION {s}.survey_group_member_market_check() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM {s}.survey_assignment_group g JOIN {s}.script_assignment_rule_version r
                           ON r.id = NEW.rule_version_id WHERE g.id = NEW.group_id AND g.market_code = r.market_code) THEN
            RAISE EXCEPTION 'a requirement group holds rules of its own market only' USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER survey_group_member_market_check BEFORE INSERT ON {s}.survey_assignment_group_member
          FOR EACH ROW EXECUTE FUNCTION {s}.survey_group_member_market_check();
    """)

    # ---- 6. permissions: created, and granted to nobody
    for code, description in PERMISSIONS.items():
        conn.execute(
            sa.text(
                f"INSERT INTO {s}.permission (id, code, alias, reserved, description) VALUES (:i, :c, NULL, false, :d)"
            ),
            {"i": uuid.uuid5(uuid.NAMESPACE_URL, "call360:permission:" + code), "c": code, "d": description},
        )


def downgrade() -> None:
    s = op.get_context().version_table_schema
    assert s in {"call360", "call360_test"}, s
    conn = op.get_bind()
    scriptless = conn.execute(
        sa.text(
            f"SELECT (SELECT count(*) FROM {s}.script_assignment_rule_version WHERE target_kind <> 'SCRIPT_VERSION') + "
            f"(SELECT count(*) FROM {s}.assignment_rule_draft WHERE target_kind <> 'SCRIPT_VERSION')"
        )
    ).scalar_one()
    if scriptless:
        # a rule that names no script cannot exist in the earlier schema, and its governed history is not thrown away
        raise RuntimeError("survey-only assignment rules exist; they cannot be expressed without the columns")
    codes = ", ".join(f"'{c}'" for c in PERMISSIONS)
    held = conn.execute(
        sa.text(
            f"SELECT count(*) FROM {s}.role_permission rp JOIN {s}.permission p ON p.id = rp.permission_id "
            f"WHERE p.code IN ({codes})"
        )
    ).scalar_one()
    if held:
        raise RuntimeError("a role holds a dedicated rule permission; revoke it deliberately before downgrading")
    before = tuple(conn.execute(sa.text(RULE_DIGEST.format(s=s))).one())
    op.execute(f"DELETE FROM {s}.permission WHERE code IN ({codes})")
    for trigger, table in (
        ("survey_group_member_market_check", "survey_assignment_group_member"),
        ("survey_binding_market_check", "survey_assignment_binding"),
        ("script_assignment_rule_kind_check", "script_assignment"),
        ("assignment_rule_draft_kind_guard", "assignment_rule_draft"),
        ("assignment_rule_market_check", "script_assignment_rule_version"),
        ("script_assignment_rule_version_market", "script_assignment_rule_version"),
    ):
        op.execute(f"DROP TRIGGER {trigger} ON {s}.{table}")
    for fn in (
        "survey_group_member_market_check", "survey_binding_market_check", "script_assignment_rule_kind_check",
        "assignment_rule_draft_kind_guard", "assignment_rule_market_check",
    ):  # fmt: skip
        op.execute(f"DROP FUNCTION {s}.{fn}()")
    op.execute(f"ALTER TABLE {s}.assignment_rule_draft DROP CONSTRAINT ck_assignment_rule_draft_frozen")
    op.execute(f"ALTER TABLE {s}.assignment_rule_draft DROP CONSTRAINT ck_assignment_rule_draft_target_kind")
    op.execute(f"ALTER TABLE {s}.assignment_rule_draft DROP COLUMN target_kind")
    op.execute(
        f"ALTER TABLE {s}.assignment_rule_draft ADD CONSTRAINT ck_assignment_rule_draft_frozen CHECK ("
        "status IN ('DRAFT', 'ABANDONED') OR (manifest IS NOT NULL AND manifest_sha256 IS NOT NULL "
        "AND target_script_version_id IS NOT NULL))"
    )
    op.execute(f"ALTER TABLE {s}.script_assignment_rule_version DROP CONSTRAINT ck_assignment_rule_target_kind")
    op.execute(f"ALTER TABLE {s}.script_assignment_rule_version ALTER COLUMN target_script_version_id SET NOT NULL")
    op.execute(f"ALTER TABLE {s}.script_assignment_rule_version DROP COLUMN target_kind, DROP COLUMN market_code")
    after = tuple(conn.execute(sa.text(RULE_DIGEST.format(s=s))).one())
    if after != before:
        raise RuntimeError("the downgrade changed an assignment rule; nothing was committed")
