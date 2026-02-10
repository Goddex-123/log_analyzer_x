"""
Log Analyzer X – Reports Page
"""
import streamlit as st
from utils.helpers import section_header_html
from reports.report_generator import generate_security_report, generate_sla_report, generate_executive_summary


def render(security_results, performance_results, usage_results, alert_summary):
    st.markdown(section_header_html("Reports Center", "Downloadable audit reports and executive summaries", "📝"), unsafe_allow_html=True)

    has_data = security_results or performance_results

    if not has_data:
        st.info("Upload and analyze log data to generate reports.")
        return

    st.markdown("""<div style="background:#1a1f2e;border:1px solid #1e293b;border-radius:10px;padding:20px;margin-bottom:20px;">
        <div style="color:#f1f5f9;font-weight:600;margin-bottom:8px;">📄 Available Reports</div>
        <div style="color:#94a3b8;font-size:0.85rem;">
            All reports are generated in HTML format with dark enterprise styling.
            They can be opened in a browser and printed to PDF.
        </div>
    </div>""", unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("""<div style="background:linear-gradient(145deg,#1a1f2e,#111827);border:1px solid #1e293b;
            border-radius:12px;padding:24px;text-align:center;border-top:3px solid #ef4444;">
            <div style="font-size:2rem;margin-bottom:8px;">🔐</div>
            <div style="color:#f1f5f9;font-weight:700;font-size:1rem;">Security Audit</div>
            <div style="color:#64748b;font-size:0.75rem;margin-top:4px;">Threats, IP reputation, MITRE mapping</div>
        </div>""", unsafe_allow_html=True)
        if security_results:
            report = generate_security_report(security_results)
            st.download_button("📥 Download Security Report", report, "security_audit_report.html", "text/html", key="sec_report")
        else:
            st.caption("No security data available")

    with col2:
        st.markdown("""<div style="background:linear-gradient(145deg,#1a1f2e,#111827);border:1px solid #1e293b;
            border-radius:12px;padding:24px;text-align:center;border-top:3px solid #3b82f6;">
            <div style="font-size:2rem;margin-bottom:8px;">⚡</div>
            <div style="color:#f1f5f9;font-weight:700;font-size:1rem;">SLA Compliance</div>
            <div style="color:#64748b;font-size:0.75rem;margin-top:4px;">Latency, health scores, breaches</div>
        </div>""", unsafe_allow_html=True)
        if performance_results:
            report = generate_sla_report(performance_results)
            st.download_button("📥 Download SLA Report", report, "sla_compliance_report.html", "text/html", key="sla_report")
        else:
            st.caption("No performance data available")

    with col3:
        st.markdown("""<div style="background:linear-gradient(145deg,#1a1f2e,#111827);border:1px solid #1e293b;
            border-radius:12px;padding:24px;text-align:center;border-top:3px solid #8b5cf6;">
            <div style="font-size:2rem;margin-bottom:8px;">📊</div>
            <div style="color:#f1f5f9;font-weight:700;font-size:1rem;">Executive Summary</div>
            <div style="color:#64748b;font-size:0.75rem;margin-top:4px;">1-page overview for leadership</div>
        </div>""", unsafe_allow_html=True)
        if security_results or performance_results:
            report = generate_executive_summary(security_results or {}, performance_results or {}, alert_summary, usage_results)
            st.download_button("📥 Download Executive Summary", report, "executive_summary.html", "text/html", key="exec_report")
        else:
            st.caption("No data available")

    # Usage stats page
    if usage_results:
        st.markdown("---")
        st.markdown(section_header_html("Usage Analytics Preview", "", "👥"), unsafe_allow_html=True)
        from visualization.charts import activity_heatmap, sankey_diagram
        col_a, col_b = st.columns(2)
        with col_a:
            heatmap_data = usage_results.get("heatmap_data", None)
            if heatmap_data is not None and not heatmap_data.empty:
                st.plotly_chart(activity_heatmap(heatmap_data), use_container_width=True)
        with col_b:
            st.markdown("##### Top Endpoints")
            top_ep = usage_results.get("top_endpoints", None)
            if top_ep is not None and not top_ep.empty:
                st.dataframe(top_ep.head(10), use_container_width=True, hide_index=True)
