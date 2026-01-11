from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Dict, Any, List, Optional, Tuple

import pandas as pd
from sqlalchemy import text

from db import engine  # uses DATABASE_URL configured for your app


# -------------------------
# Allowed fields for rules
# -------------------------
# UI Label -> DB column (proofpoint_events)
ALLOWED_FIELDS: Dict[str, str] = {
    "Email (normalized)": "email_norm",
    "Email Address": "email_address",
    "First Name": "first_name",
    "Last Name": "last_name",
    "Department": "department",
    "Manager Name": "manager_name",
    "Manager Email": "manager_email",
    "Executive Name": "executive_name",
    "Executive Email": "executive_email",
    "Campaign Title": "campaign_title",
    "Phishing Template": "phishing_template",
    "Campaign Guid": "campaign_guid",
    "Users Guid": "users_guid",
    "Clicked IP": "clicked_ip",
    "Whois Org": "whois_org",
}

# A safe list of DB columns the user can display in preview.
# (You can add more if you add more columns to proofpoint_events later.)
SAFE_COLUMNS: List[str] = [
    "id",
    "month_key",
    "batch_id",
    "email_address",
    "email_norm",
    "first_name",
    "last_name",
    "department",
    "manager_name",
    "manager_email",
    "executive_name",
    "executive_email",
    "campaign_guid",
    "users_guid",
    "campaign_title",
    "phishing_template",
    "date_sent",
    "date_opened",
    "date_clicked",
    "date_reported",
    "primary_clicked",
    "multi_click_event",
    "click_count",
    "clicked_ip",
    "whois_org",
    "is_false_positive",
    "false_positive_reason",
    "false_positive_comment",
    "false_positive_set_at",
    "false_positive_set_by",
]

DEFAULT_PREVIEW_COLUMNS: List[str] = [
    "id",
    "month_key",
    "email_address",
    "email_norm",
    "executive_name",
    "department",
    "manager_name",
    "campaign_title",
    "phishing_template",
    "clicked_ip",
    "whois_org",
    "click_count",
    "date_clicked",
    "is_false_positive",
]


@dataclass
class RuleSpec:
    scope: str  # "MONTH" or "ALL"
    month_key: Optional[date]  # required if scope == "MONTH"
    field_label: str           # must be in ALLOWED_FIELDS
    value: str                 # match value
    match_type: str            # "EXACT" | "CONTAINS" | "REGEX"
    case_insensitive: bool     # include case variants
    comment: str               # required
    created_by: str            # audit


def ensure_fp_rule_tables() -> None:
    """
    Creates FP rule + run audit tables if not present.
    Safe to call every startup.
    """
    ddl = """
    CREATE TABLE IF NOT EXISTS false_positive_rules (
        id SERIAL PRIMARY KEY,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        created_by TEXT NOT NULL,
        scope TEXT NOT NULL,                 -- 'MONTH' or 'ALL'
        month_key DATE NULL,
        field_label TEXT NOT NULL,
        field_column TEXT NOT NULL,
        match_type TEXT NOT NULL,            -- 'EXACT'/'CONTAINS'/'REGEX'
        value TEXT NOT NULL,
        case_insensitive BOOLEAN NOT NULL DEFAULT FALSE,
        comment TEXT NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS false_positive_rule_runs (
        id SERIAL PRIMARY KEY,
        rule_id INTEGER NOT NULL REFERENCES false_positive_rules(id) ON DELETE CASCADE,
        run_at TIMESTAMP NOT NULL DEFAULT NOW(),
        affected_count INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS ix_fp_rules_active ON false_positive_rules(is_active);
    CREATE INDEX IF NOT EXISTS ix_fp_rules_month_key ON false_positive_rules(month_key);
    """
    with engine.begin() as conn:
        conn.execute(text(ddl))


def _validate_rule(rule: RuleSpec) -> Tuple[bool, str]:
    if rule.scope not in ("MONTH", "ALL"):
        return False, "scope must be MONTH or ALL"
    if rule.scope == "MONTH" and not rule.month_key:
        return False, "month_key is required when scope is MONTH"
    if rule.field_label not in ALLOWED_FIELDS:
        return False, f"Invalid field: {rule.field_label}"
    if rule.match_type not in ("EXACT", "CONTAINS", "REGEX"):
        return False, "match_type must be EXACT, CONTAINS, or REGEX"
    if not rule.value or not rule.value.strip():
        return False, "value is required"
    if not rule.comment or not rule.comment.strip():
        return False, "comment is required"
    return True, ""


def _safe_selected_columns(selected: List[str]) -> List[str]:
    cols = [c for c in selected if c in SAFE_COLUMNS]
    return cols if cols else DEFAULT_PREVIEW_COLUMNS


def _build_where(rule: RuleSpec, for_case_insensitive: bool) -> Tuple[str, Dict[str, Any]]:
    """
    Returns SQL WHERE + parameters.
    IMPORTANT: This targets imported DB records.
    We ALSO restrict to click_count > 0 because you want "false positives instead of clicked".
    """
    col = ALLOWED_FIELDS[rule.field_label]
    params: Dict[str, Any] = {}

    # Scope filter
    if rule.scope == "MONTH":
        scope_sql = "month_key = :month_key"
        params["month_key"] = rule.month_key
    else:
        scope_sql = "1=1"

    # Only rows that are considered "clicked" by the data
    clicked_sql = "click_count > 0"

    # Matching behavior
    value = rule.value.strip()

    if rule.match_type == "EXACT":
        params["val"] = value
        if for_case_insensitive:
            match_sql = f"lower(coalesce({col}, '')) = lower(:val)"
        else:
            match_sql = f"coalesce({col}, '') = :val"

    elif rule.match_type == "CONTAINS":
        params["likeval"] = f"%{value}%"
        if for_case_insensitive:
            match_sql = f"lower(coalesce({col}, '')) LIKE lower(:likeval)"
        else:
            match_sql = f"coalesce({col}, '') LIKE :likeval"

    else:  # REGEX
        # Postgres regex operators: ~ (case sensitive), ~* (case-insensitive)
        params["val"] = value
        op = "~*" if for_case_insensitive else "~"
        match_sql = f"coalesce({col}, '') {op} :val"

    where_sql = f"({scope_sql}) AND ({clicked_sql}) AND ({match_sql})"
    return where_sql, params


def preview_rule(rule: RuleSpec, selected_columns: List[str], limit: int = 200) -> Dict[str, Any]:
    """
    Preview impacted imported records, with counts for exact vs case-insensitive.
    Returns a DataFrame with the selected columns.
    """
    ok, msg = _validate_rule(rule)
    if not ok:
        return {"ok": False, "error": msg}

    cols = _safe_selected_columns(selected_columns)
    cols_sql = ", ".join(cols)

    where_exact, params_exact = _build_where(rule, for_case_insensitive=False)
    where_ins, params_ins = _build_where(rule, for_case_insensitive=True)

    with engine.begin() as conn:
        exact_count = conn.execute(
            text(f"SELECT COUNT(*) FROM proofpoint_events WHERE {where_exact}"),
            params_exact
        ).scalar_one()

        ins_count = conn.execute(
            text(f"SELECT COUNT(*) FROM proofpoint_events WHERE {where_ins}"),
            params_ins
        ).scalar_one()

        # Preview uses the mode selected by the user
        where_preview, params_preview = (where_ins, params_ins) if rule.case_insensitive else (where_exact, params_exact)

        rows = conn.execute(
            text(f"""
                SELECT {cols_sql}
                FROM proofpoint_events
                WHERE {where_preview}
                ORDER BY month_key DESC, id DESC
                LIMIT :lim
            """),
            {**params_preview, "lim": int(limit)}
        ).mappings().all()

    df = pd.DataFrame(rows)

    case_hint = None
    if exact_count == 0 and ins_count > 0:
        case_hint = "Exact match found 0, but case-insensitive match found results. Enable case-insensitive to include them."
    elif exact_count != ins_count and exact_count > 0:
        case_hint = "There are case variants (e.g., ABC vs abc). Enable case-insensitive if you want to include them."

    return {
        "ok": True,
        "exact_count": int(exact_count or 0),
        "case_insensitive_count": int(ins_count or 0),
        "preview_df": df,
        "case_variant_hint": case_hint,
        "preview_limit": int(limit),
    }


def apply_rule(rule: RuleSpec) -> Dict[str, Any]:
    """
    Saves the rule, applies it by setting is_false_positive = TRUE on matching imported records.
    This makes the records disappear from reports (when exclude_false_positives is enabled).
    """
    ok, msg = _validate_rule(rule)
    if not ok:
        return {"ok": False, "error": msg}

    field_column = ALLOWED_FIELDS[rule.field_label]
    where_apply, params_apply = _build_where(rule, for_case_insensitive=rule.case_insensitive)

    with engine.begin() as conn:
        rule_id = conn.execute(
            text("""
                INSERT INTO false_positive_rules
                (created_by, scope, month_key, field_label, field_column, match_type, value, case_insensitive, comment, is_active)
                VALUES
                (:created_by, :scope, :month_key, :field_label, :field_column, :match_type, :value, :case_insensitive, :comment, TRUE)
                RETURNING id
            """),
            {
                "created_by": rule.created_by,
                "scope": rule.scope,
                "month_key": rule.month_key,
                "field_label": rule.field_label,
                "field_column": field_column,
                "match_type": rule.match_type,
                "value": rule.value.strip(),
                "case_insensitive": bool(rule.case_insensitive),
                "comment": rule.comment.strip(),
            }
        ).scalar_one()

        affected = conn.execute(
            text(f"""
                UPDATE proofpoint_events
                SET is_false_positive = TRUE,
                    false_positive_reason = :reason,
                    false_positive_comment = :fp_comment,
                    false_positive_set_at = NOW(),
                    false_positive_set_by = :fp_by
                WHERE {where_apply}
            """),
            {
                **params_apply,
                "reason": f"Rule {int(rule_id)}: {rule.field_label} {rule.match_type} '{rule.value.strip()}'",
                "fp_comment": rule.comment.strip(),
                "fp_by": rule.created_by,
            }
        ).rowcount

        conn.execute(
            text("""
                INSERT INTO false_positive_rule_runs (rule_id, affected_count)
                VALUES (:rule_id, :affected_count)
            """),
            {"rule_id": int(rule_id), "affected_count": int(affected or 0)}
        )

    return {"ok": True, "rule_id": int(rule_id), "affected_count": int(affected or 0)}


def list_rules(active_only: bool = True) -> pd.DataFrame:
    q = """
        SELECT r.id, r.created_at, r.created_by, r.scope, r.month_key,
               r.field_label, r.match_type, r.value, r.case_insensitive,
               r.comment, r.is_active
        FROM false_positive_rules r
    """
    if active_only:
        q += " WHERE r.is_active = TRUE"
    q += " ORDER BY r.created_at DESC"

    with engine.begin() as conn:
        rows = conn.execute(text(q)).mappings().all()

    return pd.DataFrame(rows)


def deactivate_rule(rule_id: int) -> Dict[str, Any]:
    with engine.begin() as conn:
        rc = conn.execute(
            text("UPDATE false_positive_rules SET is_active = FALSE WHERE id = :id"),
            {"id": int(rule_id)}
        ).rowcount

    return {"ok": True, "updated": int(rc or 0)}
