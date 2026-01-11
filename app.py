from __future__ import annotations

import io
import re
from datetime import date, datetime
from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st
from dateutil import parser as dateparser

from db import init_db, ensure_columns, engine
import processor
import proofpoint_importer
import reported_processor
import investigation
import fp_rules
import fp_actions


# -------------------------
# Initialize database
# -------------------------
try:
    init_db()
    ensure_columns()
except Exception as e:
    st.error(f"Database initialization failed: {e}")


# -------------------------
# Page configuration
# -------------------------
st.set_page_config(
    page_title="Phishing Report Management",
    page_icon=":shield:",
    layout="wide"
)


# -------------------------
# Sidebar navigation
# -------------------------
st.sidebar.title("Navigation")
page = st.sidebar.radio(
    "go to",
    ["Dashboard", "Import Data", "Reports", "Quarterly Report", "Investigation", "False Positives"]
)


# -------------------------
# Helper functions
# -------------------------
def format_number(num):
    """Format large numbers with commas"""
    if num is None:
        return "0"
    return f"{num:,}"


def month_from_filename(filename: str) -> Optional[date]:
    if not filename:
        return None
    name = filename.lower()

    m = re.search(r"(20\d{2})[-_ ]?(0[1-9]|1[0-2])", name)
    if m:
        return date(int(m.group(1)), int(m.group(2)), 1)

    month_map = {
        "jan": 1, "january": 1,
        "feb": 2, "february": 2,
        "mar": 3, "march": 3,
        "apr": 4, "april": 4,
        "may": 5,
        "jun": 6, "june": 6,
        "jul": 7, "july": 7,
        "aug": 8, "august": 8,
        "sep": 9, "sept": 9, "september": 9,
        "oct": 10, "october": 10,
        "nov": 11, "november": 11,
        "dec": 12, "december": 12,
    }

    m = re.search(r"(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t)?(?:ember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\s*[-_ ]*\s*(20\d{2})", name)
    if m:
        return date(int(m.group(2)), month_map[m.group(1)], 1)

    m = re.search(r"(20\d{2})\s*[-_ ]*\s*(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t)?(?:ember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)", name)
    if m:
        return date(int(m.group(1)), month_map[m.group(2)], 1)

    try:
        dt = dateparser.parse(filename, fuzzy=True, default=datetime(2000, 1, 1))
        if dt:
            return date(dt.year, dt.month, 1)
    except Exception:
        return None

    return None


# -------------------------
# Dashboard Page
# -------------------------
if page == "Dashboard":
    st.title(":shield: Phishing Report Management Dashboard")
    st.markdown("---")

    # Get database inventory
    try:
        inventory = processor.get_db_inventory()

        totals = inventory.get("totals", {})
        batches = inventory.get("batches", [])

        total_events = int(totals.get("events", 0) or 0)
        total_clicks = int(totals.get("click_events", 0) or 0)
        total_fp = int(totals.get("false_positive_events", 0) or 0)
        total_batches = len(batches)
        fp_rate = (total_fp / total_clicks * 100) if total_clicks else 0

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Events", format_number(total_events))

        with col2:
            st.metric("Total Batches", format_number(total_batches))

        with col3:
            st.metric("False Positives", format_number(total_fp))

        with col4:
            st.metric("FP Rate", f"{fp_rate:.1f}%")

        st.markdown("---")

        # Show monthly stats
        st.subheader("Monthly Breakdown")
        if inventory.get("months"):
            monthly_df = pd.DataFrame(inventory["months"])
            st.dataframe(monthly_df, use_container_width=True)

        # Show recent batches
        st.subheader("Recent Import Batches")
        batches = processor.list_import_batches(limit=10)
        if not batches.empty:
            st.dataframe(batches, use_container_width=True)
        else:
            st.info("No import batches found")

    except Exception as e:
        st.error(f"Error loading dashboard: {e}")


# -------------------------
# Import Data Page
# -------------------------
elif page == "Import Data":
    st.title(":inbox_tray: Import Proofpoint Data")
    st.markdown("---")

    bulk_import = st.checkbox("Bulk import from filenames (Month + Year in name)", value=False)
    uploaded_file = st.file_uploader(
        "Choose CSV file(s)",
        type="csv",
        accept_multiple_files=bulk_import
    )

    col1, col2 = st.columns(2)
    with col1:
        month_key = st.date_input("Report Month", value=date.today().replace(day=1))

    if uploaded_file is not None:
        if bulk_import:
            if st.button("Import All CSVs", type="primary"):
                with st.spinner("Importing data..."):
                    successes = []
                    failures = []
                    for f in uploaded_file:
                        inferred_month = month_from_filename(f.name)
                        if not inferred_month:
                            failures.append((f.name, "Could not infer month from filename"))
                            continue

                        try:
                            csv_bytes = f.read()
                            result = proofpoint_importer.import_proofpoint_csv(
                                csv_bytes=csv_bytes,
                                filename=f.name,
                                month_key=inferred_month
                            )
                            if result.get("ok"):
                                successes.append((f.name, result["inserted"], result["batch_id"]))
                            else:
                                failures.append((f.name, result.get("error", "Unknown error")))
                        except Exception as e:
                            failures.append((f.name, str(e)))

                    if successes:
                        st.success(f"Imported {len(successes)} file(s) successfully.")
                        st.dataframe(pd.DataFrame(successes, columns=["Filename", "Inserted", "Batch ID"]), use_container_width=True)
                    if failures:
                        st.error("Some files failed to import.")
                        st.dataframe(pd.DataFrame(failures, columns=["Filename", "Error"]), use_container_width=True)
        else:
            if st.button("Import CSV", type="primary"):
                with st.spinner("Importing data..."):
                    try:
                        # Read CSV into memory
                        csv_bytes = uploaded_file.read()

                        result = proofpoint_importer.import_proofpoint_csv(
                            csv_bytes=csv_bytes,
                            filename=uploaded_file.name,
                            month_key=month_key
                        )

                        if result.get("ok"):
                            st.success(f"Successfully imported {result['inserted']} events!")
                            st.info(f"Batch ID: {result['batch_id']}")
                            if result.get("warnings"):
                                st.warning(f"Warnings: {', '.join(result['warnings'])}")
                        else:
                            st.error(f"Import failed: {result.get('error', 'Unknown error')}")

                    except Exception as e:
                        st.error(f"Error during import: {e}")

    st.markdown("---")
    st.subheader("Manage Import Batches")

    batches = processor.list_import_batches(limit=50)
    if not batches.empty:
        st.dataframe(batches, use_container_width=True)

        batch_id_to_delete = st.number_input("Batch ID to delete", min_value=1, step=1)
        if st.button("Delete Batch", type="secondary"):
            result = processor.delete_import_batch(int(batch_id_to_delete))
            if result.get("ok"):
                st.success(f"Deleted {result['deleted_events']} events from batch {batch_id_to_delete}")
                st.rerun()
            else:
                st.error(f"Delete failed: {result.get('error', 'Unknown error')}")
    else:
        st.info("No batches to display")

    st.markdown("---")
    st.subheader(":incoming_envelope: Import Reported Email Data")

    reported_file = st.file_uploader("Choose an Excel file", type=["xlsx", "xls"], key="reported_excel")
    fallback_month = st.date_input(
        "Fallback Month (used when Created is missing)",
        value=date.today().replace(day=1),
        key="reported_month"
    )

    if reported_file is not None:
        if st.button("Import Reported Excel", type="primary", key="import_reported"):
            with st.spinner("Importing reported data..."):
                try:
                    excel_bytes = reported_file.read()
                    result = reported_processor.import_reported_excel(
                        excel_bytes=excel_bytes,
                        filename=reported_file.name,
                        fallback_month=fallback_month
                    )

                    if result.get("ok"):
                        st.success(f"Successfully imported {result['inserted']} reported items!")
                        st.info(f"Batch ID: {result['batch_id']}")
                    else:
                        st.error(f"Import failed: {result.get('error', 'Unknown error')}")
                except Exception as e:
                    st.error(f"Error during import: {e}")

    st.markdown("---")
    st.subheader("Manage Reported Import Batches")

    reported_batches = reported_processor.list_reported_import_batches(limit=50)
    if not reported_batches.empty:
        st.dataframe(reported_batches, use_container_width=True)

        reported_batch_id = st.number_input("Reported Batch ID to delete", min_value=1, step=1, key="reported_batch_delete")
        if st.button("Delete Reported Batch", type="secondary", key="delete_reported_batch"):
            result = reported_processor.delete_reported_import_batch(int(reported_batch_id))
            if result.get("ok"):
                st.success(f"Deleted {result['deleted_events']} reported items from batch {reported_batch_id}")
                st.rerun()
            else:
                st.error(f"Delete failed: {result.get('error', 'Unknown error')}")
    else:
        st.info("No reported batches to display")


# -------------------------
# Reports Page
# -------------------------
elif page == "Reports":
    st.title(":bar_chart: Phishing Summary Report")
    st.markdown("---")

    col1, col2 = st.columns(2)
    with col1:
        report_month = st.date_input("Report Month", value=date.today().replace(day=1), key="report_month")
    with col2:
        exclude_fp = st.checkbox("Exclude False Positives", value=True, key="report_exclude_fp")

    if st.button("Generate Report", type="primary"):
        with st.spinner("Generating report..."):
            try:
                from sqlalchemy import text

                # Build filter condition
                fp_filter = "AND is_false_positive = FALSE" if exclude_fp else ""

                # Query for executive summary and details
                with engine.begin() as conn:
                    # Get clicked users for the month
                    query = text(f"""
                        SELECT
                            first_name,
                            last_name,
                            email_address,
                            department,
                            manager_name,
                            raw_json->>'Region' as region,
                            executive_name
                        FROM proofpoint_events
                        WHERE month_key = :month_key
                          AND click_count > 0
                          {fp_filter}
                        ORDER BY executive_name, last_name, first_name
                    """)

                    results = conn.execute(query, {"month_key": report_month}).mappings().all()

                if not results:
                    st.info("No clicked users found for this month")
                else:
                    # Convert to DataFrame with explicit column order
                    details_df = pd.DataFrame(results)
                    details_df = details_df[['first_name', 'last_name', 'email_address', 'department', 'manager_name', 'region', 'executive_name']]

                    # Generate executive summary
                    exec_summary = details_df.groupby('executive_name').size().reset_index(name='Total Count')
                    exec_summary.columns = ['Exec / Direct reports', 'Total Count']

                    # Add Grand Total row
                    grand_total = pd.DataFrame([{
                        'Exec / Direct reports': 'Grand Total',
                        'Total Count': len(details_df)
                    }])
                    exec_summary = pd.concat([exec_summary, grand_total], ignore_index=True)

                    # Display title with month
                    st.markdown(f"## Phishing Summary Report for the Month of {report_month.strftime('%B %Y')}")
                    st.markdown("---")

                    # Display Executive Summary
                    st.dataframe(exec_summary, use_container_width=False, hide_index=True)

                    st.markdown("---")

                    # Display detailed table
                    st.subheader("Detailed Report")

                    # Rename columns to match the image exactly
                    display_df = details_df.copy()
                    display_df.columns = ['First Name', 'Last Name', 'Email Address', 'Department', 'Manager Name', 'Region', 'Executive Name']

                    st.dataframe(display_df, use_container_width=True, hide_index=True)

                    # Download buttons
                    st.markdown("---")
                    col1, col2 = st.columns(2)

                    with col1:
                        csv_summary = exec_summary.to_csv(index=False)
                        st.download_button(
                            label="Download Executive Summary CSV",
                            data=csv_summary,
                            file_name=f"executive_summary_{report_month.strftime('%Y%m')}.csv",
                            mime="text/csv"
                        )

                    with col2:
                        csv_details = display_df.to_csv(index=False)
                        st.download_button(
                            label="Download Detailed Report CSV",
                            data=csv_details,
                            file_name=f"detailed_report_{report_month.strftime('%Y%m')}.csv",
                            mime="text/csv"
                        )

                    # ======================================
                    # REPEAT OFFENDERS SECTION
                    # ======================================
                    st.markdown("---")
                    st.markdown(f"## Repeat Offenders for the Month of {report_month.strftime('%B %Y')}")
                    st.markdown("---")

                    # Calculate date range for last 12 months (including selected month)
                    from dateutil.relativedelta import relativedelta
                    start_date = report_month - relativedelta(months=11)

                    # Get users who clicked THIS month
                    current_month_emails = details_df['email_address'].unique().tolist()

                    if current_month_emails:
                        # Find which of those users have clicks in the last 12 months
                        with engine.begin() as conn:
                            repeat_query = text(f"""
                                SELECT DISTINCT
                                    email_norm,
                                    first_name,
                                    last_name,
                                    email_address,
                                    department,
                                    manager_name,
                                    raw_json->>'Region' as region,
                                    executive_name
                                FROM proofpoint_events
                                WHERE email_address = ANY(:emails)
                                  AND month_key >= :start_date
                                  AND month_key < :report_month
                                  AND click_count > 0
                                  {fp_filter}
                            """)

                            repeat_offenders = conn.execute(repeat_query, {
                                "emails": current_month_emails,
                                "start_date": start_date,
                                "report_month": report_month
                            }).mappings().all()

                        if repeat_offenders:
                            # Create summary DataFrame
                            repeat_summary_df = pd.DataFrame(repeat_offenders)
                            repeat_summary_df = repeat_summary_df[[
                                'first_name', 'last_name', 'email_address',
                                'department', 'manager_name', 'region', 'executive_name'
                            ]].drop_duplicates()

                            # Rename columns
                            repeat_summary_df.columns = [
                                'First Name', 'Last Name', 'Email Address',
                                'Department', 'Manager Name', 'Region', 'Executive Name'
                            ]

                            st.dataframe(repeat_summary_df, use_container_width=True, hide_index=True)

                            st.markdown("---")
                            st.subheader("Click History Details")

                            # Get all click details for repeat offenders in last 12 months
                            repeat_emails = repeat_summary_df['Email Address'].unique().tolist()

                            with engine.begin() as conn:
                                details_query = text(f"""
                                    SELECT
                                        first_name,
                                        last_name,
                                        email_address,
                                        TO_CHAR(month_key, 'Mon-YY') as month,
                                        phishing_template,
                                        TO_CHAR(date_clicked, 'MM/DD/YY HH24:MI') as date_time,
                                        CASE WHEN click_count > 0 THEN 'Click' ELSE '' END as event_type,
                                        clicked_ip,
                                        raw_json->>'Country' as country
                                    FROM proofpoint_events
                                    WHERE email_address = ANY(:emails)
                                      AND month_key >= :start_date
                                      AND month_key <= :report_month
                                      AND click_count > 0
                                      {fp_filter}
                                    ORDER BY email_address, date_clicked
                                """)

                                click_details = conn.execute(details_query, {
                                    "emails": repeat_emails,
                                    "start_date": start_date,
                                    "report_month": report_month
                                }).mappings().all()

                            if click_details:
                                click_details_df = pd.DataFrame(click_details)
                                # Ensure correct column order
                                click_details_df = click_details_df[['first_name', 'last_name', 'email_address', 'month', 'phishing_template', 'date_time', 'event_type', 'clicked_ip', 'country']]
                                click_details_df.columns = [
                                    'First Name', 'Last Name', 'Email Address', 'Month',
                                    'Phishing Template', 'Date & Time', 'Event Type',
                                    'IP Address', 'Country'
                                ]

                                st.dataframe(click_details_df, use_container_width=True, hide_index=True)

                                # Download buttons for repeat offenders
                                st.markdown("---")
                                col1, col2 = st.columns(2)

                                with col1:
                                    csv_repeat_summary = repeat_summary_df.to_csv(index=False)
                                    st.download_button(
                                        label="Download Repeat Offenders Summary CSV",
                                        data=csv_repeat_summary,
                                        file_name=f"repeat_offenders_summary_{report_month.strftime('%Y%m')}.csv",
                                        mime="text/csv"
                                    )

                                with col2:
                                    csv_click_history = click_details_df.to_csv(index=False)
                                    st.download_button(
                                        label="Download Click History CSV",
                                        data=csv_click_history,
                                        file_name=f"click_history_{report_month.strftime('%Y%m')}.csv",
                                        mime="text/csv"
                                    )
                            else:
                                st.info("No click history details found")
                        else:
                            st.info("No repeat offenders found for this month")
                    else:
                        st.info("No users clicked in the selected month")

            except Exception as e:
                st.error(f"Error generating report: {e}")
                import traceback
                st.code(traceback.format_exc())


# -------------------------
# Quarterly Report Page
# -------------------------
elif page == "Quarterly Report":
    st.title(":calendar: Quarterly Report")
    st.markdown("---")

    # Quarter and year selector
    col1, col2, col3 = st.columns(3)
    with col1:
        year = st.selectbox("Year", options=[2024, 2025, 2026, 2027], index=1)
    with col2:
        quarter = st.selectbox("Quarter", options=["Q1", "Q2", "Q3", "Q4"])
    with col3:
        exclude_fp = st.checkbox("Exclude False Positives", value=True, key="quarterly_exclude_fp")

    # Map quarter to months
    quarter_months = {
        "Q1": [1, 2, 3],
        "Q2": [4, 5, 6],
        "Q3": [7, 8, 9],
        "Q4": [10, 11, 12]
    }

    if st.button("Generate Quarterly Report", type="primary"):
        with st.spinner("Calculating quarterly statistics..."):
            try:
                from sqlalchemy import text
                from dateutil.relativedelta import relativedelta

                months = quarter_months[quarter]
                fp_filter = "AND is_false_positive = FALSE" if exclude_fp else ""

                # Calculate stats for each month in the quarter
                monthly_stats = []

                for month_num in months:
                    month_date = date(year, month_num, 1)

                    with engine.begin() as conn:
                        # Total clicks for the month
                        clicks_query = text(f"""
                            SELECT COUNT(DISTINCT email_address) as total_clicks
                            FROM proofpoint_events
                            WHERE month_key = :month_key
                              AND click_count > 0
                              {fp_filter}
                        """)
                        clicks_result = conn.execute(clicks_query, {"month_key": month_date}).mappings().first()
                        total_clicks = clicks_result['total_clicks'] if clicks_result else 0

                        # Total reported (from reported_events)
                        reported_query = text(f"""
                            SELECT COUNT(*) as total_reported
                            FROM reported_events
                            WHERE month_key = :month_key
                        """)
                        reported_result = conn.execute(reported_query, {"month_key": month_date}).mappings().first()
                        total_reported = reported_result['total_reported'] if reported_result else 0

                        # Repeat offenders - users who clicked this month AND have clicks in previous 11 months
                        start_date = month_date - relativedelta(months=11)

                        repeat_query = text(f"""
                            WITH current_month_clickers AS (
                                SELECT DISTINCT email_address
                                FROM proofpoint_events
                                WHERE month_key = :month_key
                                  AND click_count > 0
                                  {fp_filter}
                            )
                            SELECT COUNT(DISTINCT e.email_address) as repeat_offenders
                            FROM proofpoint_events e
                            INNER JOIN current_month_clickers c ON e.email_address = c.email_address
                            WHERE e.month_key >= :start_date
                              AND e.month_key < :month_key
                              AND e.click_count > 0
                              {fp_filter}
                        """)
                        repeat_result = conn.execute(repeat_query, {
                            "month_key": month_date,
                            "start_date": start_date
                        }).mappings().first()
                        repeat_offenders = repeat_result['repeat_offenders'] if repeat_result else 0

                    monthly_stats.append({
                        'month': month_date.strftime('%B'),
                        'total_clicks': total_clicks,
                        'total_reported': total_reported,
                        'repeat_offenders': repeat_offenders
                    })

                # Display quarterly report
                st.markdown(f"## {quarter} {year} Quarterly Statistics")
                st.markdown("---")

                # Create 3 columns for the 3 months
                cols = st.columns(3)

                for idx, stats in enumerate(monthly_stats):
                    with cols[idx]:
                        st.markdown(f"### {stats['month']}")
                        st.markdown(f"**Total Clicks** – {stats['total_clicks']}")
                        st.markdown(f"**Total Reported** – {stats['total_reported']}")
                        st.markdown(f"**Repeated Offenders** – {stats['repeat_offenders']}")
                        st.markdown("---")

                # Summary table
                st.markdown("---")
                st.subheader("Summary Table")
                summary_df = pd.DataFrame(monthly_stats)
                summary_df.columns = ['Month', 'Total Clicks', 'Total Reported', 'Repeated Offenders']
                st.dataframe(summary_df, use_container_width=True, hide_index=True)

                # Download button
                csv = summary_df.to_csv(index=False)
                st.download_button(
                    label="Download Quarterly Report CSV",
                    data=csv,
                    file_name=f"quarterly_report_{quarter}_{year}.csv",
                    mime="text/csv"
                )

            except Exception as e:
                st.error(f"Error generating quarterly report: {e}")
                import traceback
                st.code(traceback.format_exc())


# -------------------------
# Investigation Page
# -------------------------
elif page == "Investigation":
    st.title(":mag: Investigation Tool")
    st.markdown("---")

    col1, col2 = st.columns(2)
    with col1:
        include_fp = st.checkbox("Include False Positives", value=False)
    with col2:
        page_size = st.number_input("Results per page", min_value=10, max_value=1000, value=100, step=10)

    st.subheader("Display Columns")

    # Get all available fields (promoted columns + JSON fields from database)
    try:
        all_available_fields = investigation.get_available_fields()
    except:
        # Fallback to promoted columns if database query fails
        all_available_fields = [
            "id", "month_key", "batch_id", "filename",
            "email_address", "email_norm", "first_name", "last_name", "department",
            "manager_name", "manager_email", "executive_name", "executive_email",
            "campaign_guid", "users_guid", "campaign_title", "phishing_template",
            "date_sent", "date_opened", "date_clicked", "date_reported",
            "primary_clicked", "multi_click_event", "click_count",
            "clicked_ip", "whois_org",
            "is_false_positive", "false_positive_reason", "false_positive_comment"
        ]

    default_cols = [
        "id", "month_key", "email_address", "department", "executive_name",
        "campaign_title", "date_clicked", "clicked_ip", "whois_org",
        "click_count", "is_false_positive"
    ]

    selected_display_cols = st.multiselect(
        "Select columns to display (includes all promoted columns + JSON fields from your data)",
        options=all_available_fields,
        default=default_cols
    )

    st.subheader("Search Filters")

    # Use same fields for searching
    available_fields = all_available_fields

    # Simple search interface
    search_field = st.selectbox("Search Field", options=available_fields)
    search_value = st.text_input("Search Value")
    op = st.radio("Operation", ["EQUALS", "CONTAINS", "STARTS_WITH", "ENDS_WITH"], horizontal=True)
    case_insensitive = st.checkbox("Case Insensitive", value=True)

    if st.button("Search", type="primary"):
        if search_value:
            with st.spinner("Searching..."):
                try:
                    filters = []
                    if search_value:
                        filters.append(investigation.FilterSpec(
                            field=search_field,
                            op=op,
                            value=search_value,
                            case_insensitive=case_insensitive
                        ))

                    # Use selected display columns or default
                    display_fields = selected_display_cols if selected_display_cols else default_cols

                    results_df, total_count = investigation.search_events(
                        months=None,
                        include_fp=include_fp,
                        filters=filters,
                        display_fields=display_fields,
                        page_size=page_size,
                        page_num=1
                    )

                    if not results_df.empty:
                        st.success(f"Found {total_count} total results (showing {len(results_df)})")
                        st.dataframe(results_df, use_container_width=True)

                        # Download button
                        csv = results_df.to_csv(index=False)
                        st.download_button(
                            label="Download Results CSV",
                            data=csv,
                            file_name=f"investigation_results_{date.today().strftime('%Y%m%d')}.csv",
                            mime="text/csv"
                        )
                    else:
                        st.info("No results found")

                except Exception as e:
                    st.error(f"Search error: {e}")
        else:
            st.warning("Please enter a search value")


# -------------------------
# False Positives Page
# -------------------------
elif page == "False Positives":
    st.title(":clipboard: False Positives")
    st.markdown("---")

    # Initialize FP rule tables
    try:
        fp_rules.ensure_fp_rule_tables()
    except Exception as e:
        st.error(f"Error initializing FP rule tables: {e}")

    tab1, tab2, tab3 = st.tabs(["Create Rule", "Manage Rules", "Actions"])

    with tab1:
        st.subheader("Create New False Positive Rule")

        col1, col2 = st.columns(2)
        with col1:
            scope = st.radio("Scope", ["MONTH", "ALL"], horizontal=True)
            field_label = st.selectbox("Field", options=list(fp_rules.ALLOWED_FIELDS.keys()))

        with col2:
            match_type = st.radio("Match Type", ["EXACT", "CONTAINS", "REGEX"], horizontal=True)
            case_insensitive = st.checkbox("Case Insensitive", value=True, key="rule_case")

        value = st.text_input("Value to Match")
        comment = st.text_area("Comment/Reason")
        created_by = st.text_input("Created By (your name/email)")

        month_key = None
        if scope == "MONTH":
            month_key = st.date_input("Select Month", value=date.today().replace(day=1))

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Preview Rule", type="secondary"):
                if value and comment and created_by:
                    try:
                        rule = fp_rules.RuleSpec(
                            scope=scope,
                            month_key=month_key,
                            field_label=field_label,
                            value=value,
                            match_type=match_type,
                            case_insensitive=case_insensitive,
                            comment=comment,
                            created_by=created_by
                        )

                        result = fp_rules.preview_rule(
                            rule=rule,
                            selected_columns=["id", "email_address", "campaign_title", "department", "clicked_ip"],
                            limit=100
                        )

                        if result["ok"]:
                            exact_count = result["exact_count"]
                            case_count = result["case_insensitive_count"]
                            preview_df = result["preview_df"]

                            if case_insensitive:
                                st.info(f"**Preview Results**: This rule would match **{case_count}** events (case-insensitive)")
                            else:
                                st.info(f"**Preview Results**: This rule would match **{exact_count}** events (exact match)")

                            if result.get("case_variant_hint"):
                                st.warning(result["case_variant_hint"])

                            if not preview_df.empty:
                                st.dataframe(preview_df, use_container_width=True)
                            else:
                                st.warning("No matching events found")
                        else:
                            st.error(f"Preview failed: {result.get('error', 'Unknown error')}")
                    except Exception as e:
                        st.error(f"Error: {e}")
                else:
                    st.warning("Please fill in value, comment, and created_by fields")

        with col2:
            if st.button("Apply Rule", type="primary"):
                if value and comment and created_by:
                    try:
                        rule = fp_rules.RuleSpec(
                            scope=scope,
                            month_key=month_key,
                            field_label=field_label,
                            value=value,
                            match_type=match_type,
                            case_insensitive=case_insensitive,
                            comment=comment,
                            created_by=created_by
                        )

                        result = fp_rules.apply_rule(rule)

                        if result["ok"]:
                            st.success(f"Rule applied successfully! Marked {result['affected_count']} events as false positives")
                            st.info(f"Rule ID: {result['rule_id']}")
                        else:
                            st.error(f"Apply failed: {result.get('error', 'Unknown error')}")
                    except Exception as e:
                        st.error(f"Error: {e}")
                else:
                    st.warning("Please fill in value, comment, and created_by fields")

    with tab2:
        st.subheader("Active Rules")

        try:
            rules_df = fp_rules.list_rules(active_only=True)
            if not rules_df.empty:
                st.dataframe(rules_df, use_container_width=True)

                rule_id_to_deactivate = st.number_input("Rule ID to Deactivate", min_value=1, step=1)
                if st.button("Deactivate Rule"):
                    result = fp_rules.deactivate_rule(int(rule_id_to_deactivate))
                    if result["ok"]:
                        st.success(f"Rule {rule_id_to_deactivate} deactivated successfully")
                        st.rerun()
                    else:
                        st.error(f"Deactivation failed: {result.get('error', 'Unknown error')}")
            else:
                st.info("No active rules found")
        except Exception as e:
            st.error(f"Error loading rules: {e}")

    with tab3:
        st.subheader("False Positive Actions")
        st.info("Mark events as false positives based on field values")

        col1, col2 = st.columns(2)
        with col1:
            scope = st.radio("Scope", ["MONTH", "ALL"], horizontal=True, key="action_scope")
            available_fields = investigation.get_available_fields()
            field = st.selectbox("Field", options=available_fields, key="action_field")

        with col2:
            match_type = st.radio("Match Type", ["EQUALS", "CONTAINS"], horizontal=True, key="action_match")
            case_insensitive = st.checkbox("Case Insensitive", value=True, key="action_case")

        value = st.text_input("Value to Match", key="action_value")
        comment = st.text_area("Comment/Reason", key="action_comment")
        set_by = st.text_input("Set By (your name/email)", key="action_set_by")

        if scope == "MONTH":
            selected_months = st.date_input("Select Month(s)", value=date.today().replace(day=1), key="action_months")
            if not isinstance(selected_months, list):
                selected_months = [selected_months]
        else:
            selected_months = None

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Preview Action", type="secondary", key="preview_action"):
                if value and comment and set_by:
                    try:
                        action = fp_actions.FPActionSpec(
                            scope=scope,
                            months=selected_months,
                            field=field,
                            value=value,
                            match_type=match_type,
                            case_insensitive=case_insensitive,
                            comment=comment,
                            set_by=set_by
                        )

                        result = fp_actions.preview_fp(
                            action=action,
                            preview_fields=["id", "email_address", "campaign_title", "department", "clicked_ip"],
                            limit=100
                        )

                        if result["ok"]:
                            exact_count = result["exact_count"]
                            case_count = result["case_insensitive_count"]
                            preview_df = result["preview_df"]

                            if case_insensitive:
                                st.info(f"**Preview Results**: This action would mark **{case_count}** events as false positives (case-insensitive)")
                            else:
                                st.info(f"**Preview Results**: This action would mark **{exact_count}** events as false positives (exact match)")

                            if result.get("hint"):
                                st.warning(result["hint"])

                            if not preview_df.empty:
                                st.dataframe(preview_df, use_container_width=True)
                            else:
                                st.warning("No matching events found")
                        else:
                            st.error(f"Preview failed: {result.get('error', 'Unknown error')}")
                    except Exception as e:
                        st.error(f"Error: {e}")
                else:
                    st.warning("Please fill in value, comment, and set_by fields")

        with col2:
            if st.button("Apply Action", type="primary", key="apply_action"):
                if value and comment and set_by:
                    try:
                        action = fp_actions.FPActionSpec(
                            scope=scope,
                            months=selected_months,
                            field=field,
                            value=value,
                            match_type=match_type,
                            case_insensitive=case_insensitive,
                            comment=comment,
                            set_by=set_by
                        )

                        result = fp_actions.apply_fp(action)

                        if result["ok"]:
                            st.success(f"Action applied successfully! Marked {result['updated']} events as false positives")
                        else:
                            st.error(f"Apply failed: {result.get('error', 'Unknown error')}")
                    except Exception as e:
                        st.error(f"Error: {e}")
                else:
                    st.warning("Please fill in value, comment, and set_by fields")


# -------------------------
# Footer
# -------------------------
st.sidebar.markdown("---")
st.sidebar.markdown("### About")
st.sidebar.info("Phishing Report Management System v1.0")
