from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from sqlalchemy import text

from db import engine

PROMOTED_COLUMNS: List[str] = [
    "id","month_key","batch_id","filename",
    "email_address","email_norm","first_name","last_name","department",
    "manager_name","manager_email","executive_name","executive_email",
    "campaign_guid","users_guid","campaign_title","phishing_template",
    "date_sent","date_opened","date_clicked","date_reported",
    "primary_clicked","multi_click_event","click_count",
    "clicked_ip","whois_org",
    "is_false_positive","false_positive_reason","false_positive_comment","false_positive_set_at","false_positive_set_by",
]

DEFAULT_DISPLAY_COLUMNS = [
    "id","month_key","email_address","department","executive_name",
    "campaign_title","date_clicked","clicked_ip","whois_org","click_count","is_false_positive",
]

OPS = ["EQUALS","CONTAINS","STARTS_WITH","ENDS_WITH","GT","GTE","LT","LTE","IS_EMPTY","IS_NOT_EMPTY"]

NUMERIC_COLUMNS = {"id","batch_id","primary_clicked","multi_click_event","click_count"}


@dataclass
class FilterSpec:
    field: str          # can be promoted col OR json key
    op: str
    value: Optional[str]
    case_insensitive: bool


def get_json_keys(months: Optional[List[date]] = None) -> List[str]:
    """
    Returns distinct JSON keys from raw_json across the filtered dataset.
    """
    where = "1=1"
    params: Dict[str, Any] = {}
    if months:
        where = "month_key = ANY(:months)"
        params["months"] = months

    with engine.begin() as conn:
        rows = conn.execute(text(f"""
            SELECT DISTINCT jsonb_object_keys(raw_json) AS k
            FROM proofpoint_events
            WHERE {where}
              AND raw_json IS NOT NULL
            ORDER BY k
        """), params).all()

    return [r[0] for r in rows if r and r[0]]


def get_available_fields(months: Optional[List[date]] = None) -> List[str]:
    """
    Union of promoted columns + JSON keys.
    """
    keys = get_json_keys(months=months)
    # Avoid duplicates if a json key matches a promoted column name
    return PROMOTED_COLUMNS + [k for k in keys if k not in PROMOTED_COLUMNS]


def _field_expr(field: str) -> Tuple[str, Dict[str, Any]]:
    """
    Returns SQL expression to fetch/filter a field as TEXT plus its params.
    - promoted column -> CAST(col AS TEXT)
    - json key -> raw_json->>:key
    """
    if field in PROMOTED_COLUMNS:
        return f"CAST({field} AS TEXT)", {}
    return "raw_json->>:jkey", {"jkey": field}


def distinct_values(field: str, months: Optional[List[date]], include_fp: bool, limit: int = 2000) -> List[str]:
    expr, p = _field_expr(field)

    clauses = []
    params: Dict[str, Any] = {**p}

    if months:
        clauses.append("month_key = ANY(:months)")
        params["months"] = months

    if not include_fp:
        clauses.append("is_false_positive = FALSE")

    where = " AND ".join(clauses) if clauses else "1=1"

    with engine.begin() as conn:
        rows = conn.execute(text(f"""
            SELECT DISTINCT {expr} AS v
            FROM proofpoint_events
            WHERE {where}
              AND {expr} IS NOT NULL
              AND {expr} <> ''
            ORDER BY v
            LIMIT :lim
        """), {**params, "lim": int(limit)}).all()

    return [r[0] for r in rows if r and r[0] is not None]


def _build_where(months: Optional[List[date]], include_fp: bool, filters: List[FilterSpec]) -> Tuple[str, Dict[str, Any]]:
    clauses = []
    params: Dict[str, Any] = {}

    if months:
        clauses.append("month_key = ANY(:months)")
        params["months"] = months

    if not include_fp:
        clauses.append("is_false_positive = FALSE")

    for i, f in enumerate(filters):
        if f.op not in OPS:
            raise ValueError(f"Invalid op: {f.op}")
        if f.op not in ("IS_EMPTY","IS_NOT_EMPTY") and (f.value is None or str(f.value).strip() == ""):
            raise ValueError(f"Value required for {f.op}")

        expr, p = _field_expr(f.field)
        params.update({f"{k}_{i}": v for k, v in p.items()})  # scope param names per filter

        # rewrite expr param name if json key
        if "jkey" in p:
            expr = expr.replace(":jkey", f":jkey_{i}")

        val_key = f"v_{i}"

        if f.op == "IS_EMPTY":
            clauses.append(f"({expr} IS NULL OR {expr} = '')")
            continue
        if f.op == "IS_NOT_EMPTY":
            clauses.append(f"({expr} IS NOT NULL AND {expr} <> '')")
            continue

        if f.op in ("GT","GTE","LT","LTE"):
            cmp = {"GT":">","GTE":">=","LT":"<","LTE":"<="}[f.op]
            params[val_key] = str(f.value)
            # If promoted numeric column, compare numerically; else compare lexically
            if f.field in NUMERIC_COLUMNS:
                clauses.append(f"COALESCE(CAST({f.field} AS NUMERIC), 0) {cmp} CAST(:{val_key} AS NUMERIC)")
            else:
                clauses.append(f"{expr} {cmp} :{val_key}")
            continue

        # text ops
        if f.op == "EQUALS":
            params[val_key] = str(f.value)
            if f.case_insensitive:
                clauses.append(f"lower(coalesce({expr}, '')) = lower(:{val_key})")
            else:
                clauses.append(f"coalesce({expr}, '') = :{val_key}")
            continue

        if f.op == "CONTAINS":
            params[val_key] = f"%{str(f.value)}%"
            if f.case_insensitive:
                clauses.append(f"lower(coalesce({expr}, '')) LIKE lower(:{val_key})")
            else:
                clauses.append(f"coalesce({expr}, '') LIKE :{val_key}")
            continue

        if f.op == "STARTS_WITH":
            params[val_key] = f"{str(f.value)}%"
            if f.case_insensitive:
                clauses.append(f"lower(coalesce({expr}, '')) LIKE lower(:{val_key})")
            else:
                clauses.append(f"coalesce({expr}, '') LIKE :{val_key}")
            continue

        if f.op == "ENDS_WITH":
            params[val_key] = f"%{str(f.value)}"
            if f.case_insensitive:
                clauses.append(f"lower(coalesce({expr}, '')) LIKE lower(:{val_key})")
            else:
                clauses.append(f"coalesce({expr}, '') LIKE :{val_key}")
            continue

    where = " AND ".join(clauses) if clauses else "1=1"
    return where, params


def search_events(
    months: Optional[List[date]],
    include_fp: bool,
    filters: List[FilterSpec],
    display_fields: List[str],
    page_size: int,
    page_num: int
) -> Tuple[pd.DataFrame, int]:
    """
    Returns (page_df, total_count).
    Uses LIMIT/OFFSET so paging is real.
    """
    fields = display_fields[:] if display_fields else DEFAULT_DISPLAY_COLUMNS

    select_exprs = []
    params: Dict[str, Any] = {}

    # Always include id for selection management
    if "id" not in fields:
        fields = ["id"] + fields

    for f in fields:
        if f in PROMOTED_COLUMNS:
            select_exprs.append(f"{f} AS \"{f}\"")
        else:
            select_exprs.append(f"raw_json->>:k_{len(params)} AS \"{f}\"")
            params[f"k_{len(params)}"] = f

    where, wparams = _build_where(months, include_fp, filters)
    params.update(wparams)

    with engine.begin() as conn:
        total = conn.execute(text(f"""
            SELECT COUNT(*) FROM proofpoint_events WHERE {where}
        """), params).scalar_one()

        offset = max(0, (page_num - 1) * page_size)

        rows = conn.execute(text(f"""
            SELECT {", ".join(select_exprs)}
            FROM proofpoint_events
            WHERE {where}
            ORDER BY month_key DESC, id DESC
            LIMIT :lim OFFSET :off
        """), {**params, "lim": int(page_size), "off": int(offset)}).mappings().all()

    return pd.DataFrame(rows), int(total)


def fetch_by_ids(ids: List[int], display_fields: List[str]) -> pd.DataFrame:
    if not ids:
        return pd.DataFrame()

    fields = display_fields[:] if display_fields else DEFAULT_DISPLAY_COLUMNS
    if "id" not in fields:
        fields = ["id"] + fields

    select_exprs = []
    params: Dict[str, Any] = {"ids": ids}
    key_i = 0

    for f in fields:
        if f in PROMOTED_COLUMNS:
            select_exprs.append(f"{f} AS \"{f}\"")
        else:
            select_exprs.append(f"raw_json->>:k_{key_i} AS \"{f}\"")
            params[f"k_{key_i}"] = f
            key_i += 1

    with engine.begin() as conn:
        rows = conn.execute(text(f"""
            SELECT {", ".join(select_exprs)}
            FROM proofpoint_events
            WHERE id = ANY(:ids)
            ORDER BY month_key DESC, id DESC
        """), params).mappings().all()

    return pd.DataFrame(rows)
