"""
Log Analyzer X – Alerts Center Page
"""
import streamlit as st
import pandas as pd
from utils.helpers import section_header_html, kpi_card_html, alert_card_html
from alerts.alert_engine import export_alerts_csv


def render(alerts, alert_summary):
    st.markdown(section_header_html("Alerts Center", "Real-time security and performance alerts", "🚨"), unsafe_allow_html=True)

    if not alerts:
        st.info("No alerts generated. Upload log data and run analysis.")
        return

    # KPIs
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(kpi_card_html("Total Alerts", str(alert_summary.get("total", 0)), "", "🔔", accent_color="#3b82f6"), unsafe_allow_html=True)
    with c2:
        st.markdown(kpi_card_html("Critical", str(alert_summary.get("critical", 0)), "", "🚨", accent_color="#ef4444"), unsafe_allow_html=True)
    with c3:
        st.markdown(kpi_card_html("Warning", str(alert_summary.get("warning", 0)), "", "⚠️", accent_color="#f59e0b"), unsafe_allow_html=True)
    with c4:
        st.markdown(kpi_card_html("Info", str(alert_summary.get("info", 0)), "", "ℹ️", accent_color="#3b82f6"), unsafe_allow_html=True)

    st.markdown("---")

    # Filter controls
    col_f1, col_f2 = st.columns(2)
    with col_f1:
        severity_filter = st.multiselect("Filter by Severity", ["CRITICAL", "WARNING", "INFO"], default=["CRITICAL", "WARNING", "INFO"])
    with col_f2:
        categories = list(set(a.get("category", "") for a in alerts))
        category_filter = st.multiselect("Filter by Category", categories, default=categories)

    filtered = [a for a in alerts if a.get("severity") in severity_filter and a.get("category") in category_filter]

    # Export button
    csv_data = export_alerts_csv(filtered)
    if csv_data:
        st.download_button("📥 Export Alerts CSV", csv_data, "alerts_export.csv", "text/csv")

    st.markdown(f"**Showing {len(filtered)} of {len(alerts)} alerts**")

    # Alert cards
    for alert in filtered:
        st.markdown(alert_card_html(
            alert.get("title", ""),
            alert.get("description", ""),
            alert.get("severity", "INFO"),
            alert.get("timestamp", ""),
            alert.get("details", ""),
        ), unsafe_allow_html=True)
