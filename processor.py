from __future__ import annotations

import io
from datetime import date
from typing import Any, Dict, Optional, List, Tuple

import pandas as pd
from sqlalchemy import text

from db import engine, init_db, ensure_columns


# -------------------------
# Helpers
# -------------------------
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
    """
    Backward compatible:
    - new schema: import_batches.batch_id
    - legacy schema: import_batches.id
    """
    if _has_column(conn, "import_batches", "batch_id"):
        return "batch_id"
    if _has_column(conn, "import_batches", "id"):
        return "id"
    # As a last resort, add a batch_id column (non-PK) so queries can work.
    conn.execute(text("ALTER TABLE import_batches ADD COLUMN IF NOT EXISTS batch_id BIGINT;"))
    return "batch_id"


# -------------------------
# Import
# -------------------------
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

    # Proofpoint header mapping (tolerant)
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

            "primary_clicked": _to_int(r.get(col_primary), 0) if col_primary else 0,
            "multi_click_event": _to_int(r.get(col_multi), 0) if col_multi else 0,
            "click_count": _to_int(r.get(col_click_count), 0) if col_click_count else 0,

            "clicked_ip": str(r.get(col_ip)).strip() if col_ip and r.get(col_ip) is not None and str(r.get(col_ip)).strip() else None,
            "whois_org": str(r.get(col_whois)).strip() if col_whois and r.get(col_whois) is not None and str(r.get(col_whois)).strip() else None,

            "raw_json": raw,
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


# -------------------------
# Inventory / Management
# -------------------------
def get_db_inventory() -> Dict[str, Any]:
    with engine.begin() as conn:
        total = conn.execute(text("SELECT COUNT(*) FROM proofpoint_events")).scalar_one()
        click_events = conn.execute(text("SELECT COUNT(*) FROM proofpoint_events WHERE click_count > 0")).scalar_one()
        fp_events = conn.execute(text("SELECT COUNT(*) FROM proofpoint_events WHERE is_false_positive = TRUE")).scalar_one()

        months = conn.execute(text("""
            SELECT month_key, COUNT(*) AS rows
            FROM proofpoint_events
            GROUP BY month_key
            ORDER BY month_key DESC
        """)).mappings().all()

        pk = _batch_pk_col(conn)
        batches = conn.execute(text(f"""
            SELECT {pk} AS batch_id, created_at, filename, month_key, row_count
            FROM import_batches
            ORDER BY created_at DESC
            LIMIT 500
        """)).mappings().all()

    return {
        "ok": True,
        "totals": {"events": int(total), "click_events": int(click_events), "false_positive_events": int(fp_events)},
        "months": list(months),
        "batches": list(batches),
    }


def list_import_batches(limit: int = 300) -> pd.DataFrame:
    with engine.begin() as conn:
        pk = _batch_pk_col(conn)
        rows = conn.execute(text(f"""
            SELECT {pk} AS batch_id, created_at, filename, month_key, row_count
            FROM import_batches
            ORDER BY created_at DESC
            LIMIT :lim
        """), {"lim": int(limit)}).mappings().all()
    return pd.DataFrame(rows)


def delete_import_batch(batch_id: int) -> Dict[str, Any]:
    with engine.begin() as conn:
        pk = _batch_pk_col(conn)

        deleted_events = conn.execute(
            text("DELETE FROM proofpoint_events WHERE batch_id = :bid"),
            {"bid": int(batch_id)}
        ).rowcount or 0

        deleted_batches = conn.execute(
            text(f"DELETE FROM import_batches WHERE {pk} = :bid"),
            {"bid": int(batch_id)}
        ).rowcount or 0

    return {"ok": True, "deleted_events": int(deleted_events), "deleted_batches": int(deleted_batches)}


# -------------------------
# Reports (baseline so app doesn't crash)
# -------------------------
def generate_report_frames(report_month: date, repeat_threshold: int, exclude_false_positives: bool = True):
    """
    Minimal baseline report output (in-app). Keeps the app stable.
    Adjust logic to your executive summary format as needed.
    """
    where_fp = "AND is_false_positive = FALSE" if exclude_false_positives else ""

    with engine.begin() as conn:
        clicked_users = conn.execute(text(f"""
            SELECT email_norm, email_address, department, executive_name,
                   click_count, clicked_ip, whois_org, date_clicked
            FROM proofpoint_events
            WHERE month_key = :mk
              AND click_count > 0
              {where_fp}
            ORDER BY email_norm
        """), {"mk": report_month}).mappings().all()

        repeat = conn.execute(text(f"""
            SELECT email_norm,
                   SUM(click_count) AS total_clicks,
                   COUNT(*) AS months_with_clicks
            FROM proofpoint_events
            WHERE click_count > 0
              {where_fp}
            GROUP BY email_norm
            HAVING SUM(click_count) >= :thr
            ORDER BY total_clicks DESC, email_norm
        """), {"thr": int(repeat_threshold)}).mappings().all()

    clicked_df = pd.DataFrame(clicked_users)
    repeat_df = pd.DataFrame(repeat)

    exec_df = pd.DataFrame([{
        "Report Month": report_month.strftime("%b %Y"),
        "Clicked Users": int(len(clicked_df)) if not clicked_df.empty else 0,
        "Repeat Offenders (>= threshold total clicks)": int(len(repeat_df)) if not repeat_df.empty else 0,
        "Exclude False Positives": bool(exclude_false_positives),
    }])

    hist_df = pd.DataFrame()

    return exec_df, clicked_df, repeat_df, hist_df
