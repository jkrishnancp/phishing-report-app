from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from sqlalchemy import text

from db import engine
from investigation import PROMOTED_COLUMNS


@dataclass
class FPActionSpec:
    scope: str                 # "MONTH" | "ALL"
    months: Optional[List[date]]  # for MONTH scope, allow multi-month apply too
    field: str                 # promoted or json key
    value: str
    match_type: str            # "EQUALS" | "CONTAINS"
    case_insensitive: bool
    comment: str
    set_by: str


def _field_expr(field: str, suffix: str) -> Tuple[str, Dict[str, Any]]:
    if field in PROMOTED_COLUMNS:
        return f"CAST({field} AS TEXT)", {}
    return "raw_json->>:jkey_" + suffix, {f"jkey_{suffix}": field}


def _validate(action: FPActionSpec) -> Tuple[bool, str]:
    if action.scope not in ("MONTH", "ALL"):
        return False, "scope must be MONTH or ALL"
    if action.scope == "MONTH" and not action.months:
        return False, "months required when scope is MONTH"
    if action.match_type not in ("EQUALS", "CONTAINS"):
        return False, "match_type must be EQUALS or CONTAINS"
    if not action.value or not str(action.value).strip():
        return False, "value required"
    if not action.comment or not str(action.comment).strip():
        return False, "comment required"
    return True, ""


def _scope_where(action: FPActionSpec) -> Tuple[str, Dict[str, Any]]:
    if action.scope == "ALL":
        return "1=1", {}
    return "month_key = ANY(:months)", {"months": action.months}


def preview_fp(action: FPActionSpec, preview_fields: List[str], limit: int = 200) -> Dict[str, Any]:
    ok, msg = _validate(action)
    if not ok:
        return {"ok": False, "error": msg}

    scope_sql, scope_params = _scope_where(action)

    expr_exact, p1 = _field_expr(action.field, "0")
    expr_ins, p2 = _field_expr(action.field, "1")
    expr_apply, p3 = _field_expr(action.field, "2")

    def where_match(expr: str, key: str, ci: bool) -> Tuple[str, Dict[str, Any]]:
        params: Dict[str, Any] = {key: action.value.strip()}
        if action.match_type == "EQUALS":
            if ci:
                return f"lower(coalesce({expr},'')) = lower(:{key})", params
            return f"coalesce({expr},'') = :{key}", params
        # CONTAINS
        params[key] = f"%{action.value.strip()}%"
        if ci:
            return f"lower(coalesce({expr},'')) LIKE lower(:{key})", params
        return f"coalesce({expr},'') LIKE :{key}", params

    w_exact, wp_exact = where_match(expr_exact, "val0", False)
    w_ins, wp_ins = where_match(expr_ins, "val1", True)
    w_apply, wp_apply = where_match(expr_apply, "val2", action.case_insensitive)

    base_click = "click_count > 0"

    # Build preview SELECT
    fields = preview_fields[:] if preview_fields else ["id","month_key","email_address","clicked_ip","whois_org","campaign_title","date_clicked","click_count","is_false_positive"]
    if "id" not in fields:
        fields = ["id"] + fields

    select_exprs = []
    params: Dict[str, Any] = {}
    key_i = 0
    for f in fields:
        if f in PROMOTED_COLUMNS:
            select_exprs.append(f"{f} AS \"{f}\"")
        else:
            select_exprs.append(f"raw_json->>:k_{key_i} AS \"{f}\"")
            params[f"k_{key_i}"] = f
            key_i += 1

    with engine.begin() as conn:
        exact_count = conn.execute(text(f"""
            SELECT COUNT(*)
            FROM proofpoint_events
            WHERE ({scope_sql}) AND ({base_click}) AND ({w_exact})
        """), {**scope_params, **p1, **wp_exact}).scalar_one()

        ins_count = conn.execute(text(f"""
            SELECT COUNT(*)
            FROM proofpoint_events
            WHERE ({scope_sql}) AND ({base_click}) AND ({w_ins})
        """), {**scope_params, **p2, **wp_ins}).scalar_one()

        rows = conn.execute(text(f"""
            SELECT {", ".join(select_exprs)}
            FROM proofpoint_events
            WHERE ({scope_sql}) AND ({base_click}) AND ({w_apply})
            ORDER BY month_key DESC, id DESC
            LIMIT :lim
        """), {**scope_params, **p3, **wp_apply, **params, "lim": int(limit)}).mappings().all()

    hint = None
    if exact_count == 0 and ins_count > 0:
        hint = "Exact match found 0, but case-insensitive match found results. Enable case-insensitive."
    elif exact_count != ins_count and exact_count > 0:
        hint = "Case variants exist (ABC vs abc). Enable case-insensitive if desired."

    return {
        "ok": True,
        "exact_count": int(exact_count or 0),
        "case_insensitive_count": int(ins_count or 0),
        "preview_df": pd.DataFrame(rows),
        "hint": hint,
    }


def apply_fp(action: FPActionSpec) -> Dict[str, Any]:
    ok, msg = _validate(action)
    if not ok:
        return {"ok": False, "error": msg}

    scope_sql, scope_params = _scope_where(action)
    expr, p = _field_expr(action.field, "a")

    base_click = "click_count > 0"

    if action.match_type == "EQUALS":
        if action.case_insensitive:
            match_sql = f"lower(coalesce({expr},'')) = lower(:val)"
        else:
            match_sql = f"coalesce({expr},'') = :val"
        val = action.value.strip()
    else:
        if action.case_insensitive:
            match_sql = f"lower(coalesce({expr},'')) LIKE lower(:val)"
        else:
            match_sql = f"coalesce({expr},'') LIKE :val"
        val = f"%{action.value.strip()}%"

    with engine.begin() as conn:
        rc = conn.execute(text(f"""
            UPDATE proofpoint_events
            SET is_false_positive = TRUE,
                false_positive_reason = :reason,
                false_positive_comment = :comment,
                false_positive_set_at = NOW(),
                false_positive_set_by = :set_by
            WHERE ({scope_sql}) AND ({base_click}) AND ({match_sql})
        """), {
            **scope_params,
            **p,
            "val": val,
            "reason": f"Investigation FP: {action.field} {action.match_type} '{action.value.strip()}'",
            "comment": action.comment.strip(),
            "set_by": action.set_by.strip() if action.set_by else "unknown",
        }).rowcount

    return {"ok": True, "updated": int(rc or 0)}
