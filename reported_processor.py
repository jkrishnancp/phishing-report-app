from __future__ import annotations

import io
import json
from datetime import date
from typing import Any, Dict, Optional

import pandas as pd
from sqlalchemy import text

from db import engine, init_db, ensure_columns


def _to_ts(x: Any):
    if x is None or (isinstance(x, float) and pd.isna(x)):
        return None
    s = str(x).strip()
    if not s:
        return None
    try:
        return pd.to_datetime(s, errors="coerce")
    except Exception:
        return None


def _pick(df: pd.DataFrame, *names: str) -> Optional[str]:
    cols = {c.strip(): c for c in df.columns}
    for n in names:
        if n in df.columns:
            return n
        if n.strip() in cols:
            return cols[n.strip()]
    return None


def _has_column(conn, table: str, col: str) -> bool:
    q = text("""
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = :t AND column_name = :c
        LIMIT 1
    """)
    return conn.execute(q, {"t": table, "c": col}).first() is not None


def _reported_batch_pk_col(conn) -> str:
    if _has_column(conn, "reported_import_batches", "batch_id"):
        return "batch_id"
    if _has_column(conn, "reported_import_batches", "id"):
        return "id"
    conn.execute(text("ALTER TABLE reported_import_batches ADD COLUMN IF NOT EXISTS batch_id BIGINT;"))
    return "batch_id"


def _month_key_for_import(fallback_month: date) -> date:
    return fallback_month


def import_reported_excel(
    excel_bytes: bytes,
    filename: str,
    fallback_month: date
) -> Dict[str, Any]:
    init_db()
    ensure_columns()

    try:
        df = pd.read_excel(io.BytesIO(excel_bytes))
    except Exception as e:
        return {"ok": False, "error": f"Excel read failed: {e}"}

    if df is None or df.empty:
        return {"ok": False, "error": "Excel is empty"}

    with engine.begin() as conn:
        pk = _reported_batch_pk_col(conn)
        batch_id = conn.execute(
            text(f"""
                INSERT INTO reported_import_batches (filename, row_count)
                VALUES (:filename, 0)
                RETURNING {pk}
            """),
            {"filename": filename}
        ).scalar_one()

    col_issue_type = _pick(df, "Issue Type", "issue_type")
    col_issue_key = _pick(df, "Issue key", "Issue Key", "issue_key")
    col_issue_id = _pick(df, "Issue id", "Issue Id", "issue_id")
    col_summary = _pick(df, "Summary", "summary")
    col_created = _pick(df, "Created", "created")
    col_risk = _pick(df, "Custom field (Risk Accepted)", "Risk Accepted", "risk_accepted")
    col_assignee = _pick(df, "Assignee", "assignee")
    col_assignee_id = _pick(df, "Assignee Id", "Assignee ID", "assignee_id")
    col_reporter = _pick(df, "Reporter", "reporter")
    col_reporter_id = _pick(df, "Reporter Id", "Reporter ID", "reporter_id")
    col_priority = _pick(df, "Priority", "priority")
    col_status = _pick(df, "Status", "status")
    col_due = _pick(df, "Due date", "Due Date", "due_date")
    col_remediation = _pick(df, "Custom field (Remediation Steps)", "Remediation Steps", "remediation_steps")
    col_reason = _pick(df, "Custom field (Reason For Closing)", "Reason For Closing", "reason_for_closing")

    rows = []
    for _, r in df.iterrows():
        raw = {}
        for c in df.columns:
            v = r.get(c, None)
            if pd.isna(v):
                raw[c] = None
            elif isinstance(v, pd.Timestamp):
                raw[c] = v.isoformat()
            else:
                raw[c] = v if isinstance(v, (int, float, bool, str)) else str(v)

        created_ts = _to_ts(r.get(col_created)) if col_created else None

        rows.append({
            "month_key": _month_key_for_import(fallback_month),
            "batch_id": int(batch_id),
            "filename": filename,
            "issue_type": str(r.get(col_issue_type)).strip() if col_issue_type and r.get(col_issue_type) is not None and str(r.get(col_issue_type)).strip() else None,
            "issue_key": str(r.get(col_issue_key)).strip() if col_issue_key and r.get(col_issue_key) is not None and str(r.get(col_issue_key)).strip() else None,
            "issue_id": str(r.get(col_issue_id)).strip() if col_issue_id and r.get(col_issue_id) is not None and str(r.get(col_issue_id)).strip() else None,
            "summary": str(r.get(col_summary)).strip() if col_summary and r.get(col_summary) is not None and str(r.get(col_summary)).strip() else None,
            "created_at": created_ts,
            "risk_accepted": str(r.get(col_risk)).strip() if col_risk and r.get(col_risk) is not None and str(r.get(col_risk)).strip() else None,
            "assignee": str(r.get(col_assignee)).strip() if col_assignee and r.get(col_assignee) is not None and str(r.get(col_assignee)).strip() else None,
            "assignee_id": str(r.get(col_assignee_id)).strip() if col_assignee_id and r.get(col_assignee_id) is not None and str(r.get(col_assignee_id)).strip() else None,
            "reporter": str(r.get(col_reporter)).strip() if col_reporter and r.get(col_reporter) is not None and str(r.get(col_reporter)).strip() else None,
            "reporter_id": str(r.get(col_reporter_id)).strip() if col_reporter_id and r.get(col_reporter_id) is not None and str(r.get(col_reporter_id)).strip() else None,
            "priority": str(r.get(col_priority)).strip() if col_priority and r.get(col_priority) is not None and str(r.get(col_priority)).strip() else None,
            "status": str(r.get(col_status)).strip() if col_status and r.get(col_status) is not None and str(r.get(col_status)).strip() else None,
            "due_date": _to_ts(r.get(col_due)) if col_due else None,
            "remediation_steps": str(r.get(col_remediation)).strip() if col_remediation and r.get(col_remediation) is not None and str(r.get(col_remediation)).strip() else None,
            "reason_for_closing": str(r.get(col_reason)).strip() if col_reason and r.get(col_reason) is not None and str(r.get(col_reason)).strip() else None,
            "raw_json": json.dumps(raw),
        })

    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO reported_events (
                    month_key, batch_id, filename,
                    issue_type, issue_key, issue_id, summary,
                    created_at, risk_accepted,
                    assignee, assignee_id,
                    reporter, reporter_id,
                    priority, status, due_date,
                    remediation_steps, reason_for_closing,
                    raw_json
                )
                VALUES (
                    :month_key, :batch_id, :filename,
                    :issue_type, :issue_key, :issue_id, :summary,
                    :created_at, :risk_accepted,
                    :assignee, :assignee_id,
                    :reporter, :reporter_id,
                    :priority, :status, :due_date,
                    :remediation_steps, :reason_for_closing,
                    :raw_json
                )
            """),
            rows
        )

        pk = _reported_batch_pk_col(conn)
        conn.execute(
            text(f"UPDATE reported_import_batches SET row_count = :rc WHERE {pk} = :bid"),
            {"rc": len(rows), "bid": int(batch_id)}
        )

    return {"ok": True, "batch_id": int(batch_id), "inserted": len(rows)}


def list_reported_import_batches(limit: int = 300) -> pd.DataFrame:
    with engine.begin() as conn:
        pk = _reported_batch_pk_col(conn)
        rows = conn.execute(text(f"""
            SELECT {pk} AS batch_id, created_at, filename, row_count
            FROM reported_import_batches
            ORDER BY created_at DESC
            LIMIT :lim
        """), {"lim": int(limit)}).mappings().all()
    return pd.DataFrame(rows)


def delete_reported_import_batch(batch_id: int) -> Dict[str, Any]:
    with engine.begin() as conn:
        pk = _reported_batch_pk_col(conn)

        deleted_events = conn.execute(
            text("DELETE FROM reported_events WHERE batch_id = :bid"),
            {"bid": int(batch_id)}
        ).rowcount or 0

        deleted_batches = conn.execute(
            text(f"DELETE FROM reported_import_batches WHERE {pk} = :bid"),
            {"bid": int(batch_id)}
        ).rowcount or 0

    return {"ok": True, "deleted_events": int(deleted_events), "deleted_batches": int(deleted_batches)}
