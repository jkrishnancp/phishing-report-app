from __future__ import annotations

import io
import json
from datetime import date
from typing import Any, Dict, Optional

import pandas as pd
from sqlalchemy import text

from db import engine, init_db, ensure_columns


def _norm_email(x: Any) -> Optional[str]:
    if x is None:
        return None
    s = str(x).strip().lower()
    return s if s else None


def _to_int(x: Any, default: int = 0) -> int:
    try:
        if pd.isna(x):
            return default
        return int(float(x))
    except Exception:
        return default


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


def _batch_pk_col(conn) -> str:
    if _has_column(conn, "import_batches", "batch_id"):
        return "batch_id"
    if _has_column(conn, "import_batches", "id"):
        return "id"
    conn.execute(text("ALTER TABLE import_batches ADD COLUMN IF NOT EXISTS batch_id BIGINT;"))
    return "batch_id"


def import_proofpoint_csv(
    csv_bytes: bytes,
    month_key: date,
    filename: str,
    replace_month: bool = True
) -> Dict[str, Any]:
    init_db()
    ensure_columns()

    try:
        df = pd.read_csv(io.BytesIO(csv_bytes))
    except Exception as e:
        return {"ok": False, "error": f"CSV read failed: {e}"}

    if df is None or df.empty:
        return {"ok": False, "error": "CSV is empty"}

    with engine.begin() as conn:
        pk = _batch_pk_col(conn)
        batch_id = conn.execute(
            text(f"""
                INSERT INTO import_batches (filename, month_key, row_count)
                VALUES (:filename, :month_key, 0)
                RETURNING {pk}
            """),
            {"filename": filename, "month_key": month_key}
        ).scalar_one()

        if replace_month:
            conn.execute(
                text("DELETE FROM proofpoint_events WHERE month_key = :month_key"),
                {"month_key": month_key}
            )

    col_email = _pick(df, "Email", "Email Address", "email", "email_address")
    col_first = _pick(df, "First Name", "first_name")
    col_last = _pick(df, "Last Name", "last_name")
    col_dept = _pick(df, "Department", "department")
    col_mgr = _pick(df, "Manager Name", "manager_name")
    col_mgr_email = _pick(df, "Manager Email", "manager_email")
    col_exec = _pick(df, "Executive Name", "executive_name")
    col_exec_email = _pick(df, "Executive Email", "executive_email")

    col_camp_guid = _pick(df, "Campaign Guid", "campaign_guid", "Campaign GUID")
    col_user_guid = _pick(df, "Users Guid", "users_guid", "User GUID")
    col_camp_title = _pick(df, "Campaign Title", "campaign_title")
    col_template = _pick(df, "Phishing Template", "Template", "phishing_template")

    col_sent = _pick(df, "Date Sent", "date_sent")
    col_opened = _pick(df, "Date Opened", "date_opened")
    col_clicked = _pick(df, "Date Clicked", "date_clicked")
    col_reported = _pick(df, "Date Reported", "date_reported")

    col_primary = _pick(df, "Primary Clicked", "primary_clicked")
    col_multi = _pick(df, "Multi Click Event", "multi_click_event")
    col_click_count = _pick(df, "Click Count", "click_count")

    col_ip = _pick(df, "Clicked IP", "Source IP", "clicked_ip")
    col_whois = _pick(df, "Whois Organization", "Whois Org", "whois_org")

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

        email = r.get(col_email) if col_email else None
        email_norm = _norm_email(email)

        primary_clicked = _to_int(r.get(col_primary), 0) if col_primary else 0
        multi_click_event = _to_int(r.get(col_multi), 0) if col_multi else 0
        click_count_raw = _to_int(r.get(col_click_count), 0) if col_click_count else 0
        click_count = click_count_raw
        if click_count == 0 and (primary_clicked > 0 or multi_click_event > 0):
            click_count = max(primary_clicked, 0) + max(multi_click_event, 0)

        rows.append({
            "month_key": month_key,
            "batch_id": int(batch_id),
            "filename": filename,

            "email_address": str(email).strip() if email is not None and str(email).strip() else None,
            "email_norm": email_norm,

            "first_name": str(r.get(col_first)).strip() if col_first and r.get(col_first) is not None and str(r.get(col_first)).strip() else None,
            "last_name": str(r.get(col_last)).strip() if col_last and r.get(col_last) is not None and str(r.get(col_last)).strip() else None,
            "department": str(r.get(col_dept)).strip() if col_dept and r.get(col_dept) is not None and str(r.get(col_dept)).strip() else None,

            "manager_name": str(r.get(col_mgr)).strip() if col_mgr and r.get(col_mgr) is not None and str(r.get(col_mgr)).strip() else None,
            "manager_email": str(r.get(col_mgr_email)).strip() if col_mgr_email and r.get(col_mgr_email) is not None and str(r.get(col_mgr_email)).strip() else None,

            "executive_name": str(r.get(col_exec)).strip() if col_exec and r.get(col_exec) is not None and str(r.get(col_exec)).strip() else None,
            "executive_email": str(r.get(col_exec_email)).strip() if col_exec_email and r.get(col_exec_email) is not None and str(r.get(col_exec_email)).strip() else None,

            "campaign_guid": str(r.get(col_camp_guid)).strip() if col_camp_guid and r.get(col_camp_guid) is not None and str(r.get(col_camp_guid)).strip() else None,
            "users_guid": str(r.get(col_user_guid)).strip() if col_user_guid and r.get(col_user_guid) is not None and str(r.get(col_user_guid)).strip() else None,

            "campaign_title": str(r.get(col_camp_title)).strip() if col_camp_title and r.get(col_camp_title) is not None and str(r.get(col_camp_title)).strip() else None,
            "phishing_template": str(r.get(col_template)).strip() if col_template and r.get(col_template) is not None and str(r.get(col_template)).strip() else None,

            "date_sent": _to_ts(r.get(col_sent)) if col_sent else None,
            "date_opened": _to_ts(r.get(col_opened)) if col_opened else None,
            "date_clicked": _to_ts(r.get(col_clicked)) if col_clicked else None,
            "date_reported": _to_ts(r.get(col_reported)) if col_reported else None,

            "primary_clicked": primary_clicked,
            "multi_click_event": multi_click_event,
            "click_count": click_count,

            "clicked_ip": str(r.get(col_ip)).strip() if col_ip and r.get(col_ip) is not None and str(r.get(col_ip)).strip() else None,
            "whois_org": str(r.get(col_whois)).strip() if col_whois and r.get(col_whois) is not None and str(r.get(col_whois)).strip() else None,

            "raw_json": json.dumps(raw),
        })

    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO proofpoint_events (
                    month_key, batch_id, filename,
                    email_address, email_norm, first_name, last_name, department,
                    manager_name, manager_email,
                    executive_name, executive_email,
                    campaign_guid, users_guid, campaign_title, phishing_template,
                    date_sent, date_opened, date_clicked, date_reported,
                    primary_clicked, multi_click_event, click_count,
                    clicked_ip, whois_org,
                    raw_json
                )
                VALUES (
                    :month_key, :batch_id, :filename,
                    :email_address, :email_norm, :first_name, :last_name, :department,
                    :manager_name, :manager_email,
                    :executive_name, :executive_email,
                    :campaign_guid, :users_guid, :campaign_title, :phishing_template,
                    :date_sent, :date_opened, :date_clicked, :date_reported,
                    :primary_clicked, :multi_click_event, :click_count,
                    :clicked_ip, :whois_org,
                    :raw_json
                )
            """),
            rows
        )

        pk = _batch_pk_col(conn)
        conn.execute(
            text(f"UPDATE import_batches SET row_count = :rc WHERE {pk} = :bid"),
            {"rc": len(rows), "bid": int(batch_id)}
        )

    return {"ok": True, "batch_id": int(batch_id), "inserted": len(rows)}
