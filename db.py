from __future__ import annotations

import os
from sqlalchemy import create_engine, text

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://postgres:postgres@db:5432/postgres")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    future=True,
)


def init_db() -> None:
    """
    Creates tables if they don't exist, and ensures required columns exist.
    This is intentionally conservative (no destructive migrations).
    """
    with engine.begin() as conn:
        # Core table
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS proofpoint_events (
            id BIGSERIAL PRIMARY KEY,
            month_key DATE NOT NULL,
            batch_id BIGINT,
            filename TEXT,

            -- Promoted fields (common investigation/reporting)
            email_address TEXT,
            email_norm TEXT,
            first_name TEXT,
            last_name TEXT,
            department TEXT,
            manager_name TEXT,
            manager_email TEXT,
            executive_name TEXT,
            executive_email TEXT,

            campaign_guid TEXT,
            users_guid TEXT,
            campaign_title TEXT,
            phishing_template TEXT,

            date_sent TIMESTAMP NULL,
            date_opened TIMESTAMP NULL,
            date_clicked TIMESTAMP NULL,
            date_reported TIMESTAMP NULL,

            primary_clicked INTEGER DEFAULT 0,
            multi_click_event INTEGER DEFAULT 0,
            click_count INTEGER DEFAULT 0,

            clicked_ip TEXT,
            whois_org TEXT,

            is_false_positive BOOLEAN NOT NULL DEFAULT FALSE,
            false_positive_reason TEXT,
            false_positive_comment TEXT,
            false_positive_set_at TIMESTAMP NULL,
            false_positive_set_by TEXT,

            -- Full-fidelity row copy (dynamic fields)
            raw_json JSONB
        );
        """))

        # Helpful indexes
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_pe_month_key ON proofpoint_events(month_key);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_pe_email_norm ON proofpoint_events(email_norm);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_pe_clicked_ip ON proofpoint_events(clicked_ip);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_pe_fp ON proofpoint_events(is_false_positive);"))

        # Batch table
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS import_batches (
            batch_id BIGSERIAL PRIMARY KEY,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            filename TEXT,
            month_key DATE NOT NULL,
            row_count INTEGER NOT NULL DEFAULT 0
        );
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_batches_month_key ON import_batches(month_key);"))

        # Reported email (ticket) table
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS reported_events (
            id BIGSERIAL PRIMARY KEY,
            month_key DATE NOT NULL,
            batch_id BIGINT,
            filename TEXT,

            issue_type TEXT,
            issue_key TEXT,
            issue_id TEXT,
            summary TEXT,
            created_at TIMESTAMP NULL,
            risk_accepted TEXT,
            assignee TEXT,
            assignee_id TEXT,
            reporter TEXT,
            reporter_id TEXT,
            priority TEXT,
            status TEXT,
            due_date TIMESTAMP NULL,
            remediation_steps TEXT,
            reason_for_closing TEXT,

            raw_json JSONB
        );
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_re_month_key ON reported_events(month_key);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_re_issue_id ON reported_events(issue_id);"))

        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS reported_import_batches (
            batch_id BIGSERIAL PRIMARY KEY,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            filename TEXT,
            row_count INTEGER NOT NULL DEFAULT 0
        );
        """))


def ensure_columns() -> None:
    """
    If you already had an older schema, this adds missing columns safely.
    """
    with engine.begin() as conn:
        # Ensure reported tables exist (legacy safe)
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS reported_events (
            id BIGSERIAL PRIMARY KEY,
            month_key DATE NOT NULL,
            batch_id BIGINT,
            filename TEXT,
            issue_type TEXT,
            issue_key TEXT,
            issue_id TEXT,
            summary TEXT,
            created_at TIMESTAMP NULL,
            risk_accepted TEXT,
            assignee TEXT,
            assignee_id TEXT,
            reporter TEXT,
            reporter_id TEXT,
            priority TEXT,
            status TEXT,
            due_date TIMESTAMP NULL,
            remediation_steps TEXT,
            reason_for_closing TEXT,
            raw_json JSONB
        );
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_re_month_key ON reported_events(month_key);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_re_issue_id ON reported_events(issue_id);"))

        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS reported_import_batches (
            batch_id BIGSERIAL PRIMARY KEY,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            filename TEXT,
            row_count INTEGER NOT NULL DEFAULT 0
        );
        """))

        # Ensure proofpoint_events has required columns
        required_cols = {
            "filename": "TEXT",
            "raw_json": "JSONB",
            "is_false_positive": "BOOLEAN NOT NULL DEFAULT FALSE",
            "false_positive_reason": "TEXT",
            "false_positive_comment": "TEXT",
            "false_positive_set_at": "TIMESTAMP NULL",
            "false_positive_set_by": "TEXT",
        }

        for col, ddl in required_cols.items():
            conn.execute(text(f"ALTER TABLE proofpoint_events ADD COLUMN IF NOT EXISTS {col} {ddl};"))

        # Ensure is_false_positive defaults are enforced for legacy rows/schemas
        conn.execute(text("ALTER TABLE proofpoint_events ALTER COLUMN is_false_positive SET DEFAULT FALSE;"))
        conn.execute(text("UPDATE proofpoint_events SET is_false_positive = FALSE WHERE is_false_positive IS NULL;"))

        # Handle import_batches schema migration
        # Check if uploaded_at exists and created_at doesn't, then rename
        result = conn.execute(text("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'import_batches' AND column_name IN ('uploaded_at', 'created_at')
        """))
        columns = [row[0] for row in result]

        if 'uploaded_at' in columns and 'created_at' not in columns:
            conn.execute(text("ALTER TABLE import_batches RENAME COLUMN uploaded_at TO created_at;"))

        # Ensure import_batches has required columns
        conn.execute(text("ALTER TABLE import_batches ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT NOW();"))
        conn.execute(text("ALTER TABLE import_batches ADD COLUMN IF NOT EXISTS filename TEXT;"))
        conn.execute(text("ALTER TABLE import_batches ADD COLUMN IF NOT EXISTS month_key DATE;"))
        conn.execute(text("ALTER TABLE import_batches ADD COLUMN IF NOT EXISTS row_count INTEGER NOT NULL DEFAULT 0;"))
        # Ensure created_at has a default for legacy schemas
        conn.execute(text("ALTER TABLE import_batches ALTER COLUMN created_at SET DEFAULT NOW();"))
        conn.execute(text("UPDATE import_batches SET created_at = NOW() WHERE created_at IS NULL;"))
