"""
Log Analyzer X – Executive Dashboard Page
C-Level overview with system health, risk index, top threats, KPIs.
"""
import streamlit as st
from utils.helpers import kpi_card_html, section_header_html, format_number, format_percentage, rag_badge_html


def render(df, security_results, performance_results, usage_results, anomaly_results, alert_summary, risk_summary):
    st.markdown(section_header_html("Executive Dashboard", "Real-time system intelligence overview", "📊"), unsafe_allow_html=True)

    # ─── Top KPI Row ──────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    health = performance_results.get("overall_health_score", 0) if performance_results else 0
    risk_idx = security_results.get("risk_index", 0) if security_results else 0
    total_alerts = alert_summary.get("total", 0) if alert_summary else 0
    total_requests = len(df)

    with c1:
        st.markdown(kpi_card_html("System Health", f"{health:.0f}/100", "Composite service score", "💚",
                                  accent_color="#10b981" if health > 80 else "#f59e0b"), unsafe_allow_html=True)
    with c2:
        st.markdown(kpi_card_html("Security Risk", f"{risk_idx}/100", "Threat assessment index", "🔐",
                                  accent_color="#ef4444" if risk_idx > 50 else "#3b82f6"), unsafe_allow_html=True)
    with c3:
        st.markdown(kpi_card_html("Total Events", format_number(total_requests, 0), "Log records analyzed", "📋",
                                  accent_color="#8b5cf6"), unsafe_allow_html=True)
    with c4:
        st.markdown(kpi_card_html("Active Alerts", str(total_alerts),
                                  f"{alert_summary.get('critical', 0)} critical" if alert_summary else "",
                                  "🚨", accent_color="#ef4444" if total_alerts > 0 else "#10b981"), unsafe_allow_html=True)

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    # ─── Second KPI Row ───────────────────────────────────────
    c5, c6, c7, c8 = st.columns(4)
    failure_rate = security_results.get("failure_rate", 0) if security_results else 0
    total_users = usage_results.get("total_users", 0) if usage_results else 0
    suspicious = usage_results.get("suspicious_users", 0) if usage_results else 0
    sla_breaches = performance_results.get("services_breaching_sla", 0) if performance_results else 0

    with c5:
        st.markdown(kpi_card_html("Failure Rate", format_percentage(failure_rate), "Authentication failures", "⚡",
                                  accent_color="#f59e0b"), unsafe_allow_html=True)
    with c6:
        st.markdown(kpi_card_html("Users Analyzed", format_number(total_users, 0), f"{suspicious} suspicious", "👥",
                                  accent_color="#06b6d4"), unsafe_allow_html=True)
    with c7:
        st.markdown(kpi_card_html("SLA Breaches", str(sla_breaches), "Services exceeding thresholds", "📉",
                                  accent_color="#ef4444" if sla_breaches > 0 else "#10b981"), unsafe_allow_html=True)
    with c8:
        threats = security_results.get("total_threats", 0) if security_results else 0
        st.markdown(kpi_card_html("Threats Detected", str(threats), "Brute force + credential stuffing", "🎯",
                                  accent_color="#ef4444" if threats > 0 else "#10b981"), unsafe_allow_html=True)

    st.markdown("---")

    # ─── Charts Row ───────────────────────────────────────────
    from visualization.charts import throughput_chart, service_health_gauge, risk_distribution_chart

    col_l, col_r = st.columns([3, 2])
    with col_l:
        if performance_results and "throughput" in performance_results:
            st.plotly_chart(throughput_chart(performance_results["throughput"]), use_container_width=True)
    with col_r:
        if performance_results and "service_health" in performance_results:
            health_df = performance_results["service_health"]
            if not health_df.empty:
                st.plotly_chart(service_health_gauge(health_df), use_container_width=True)

    # ─── Top Threats & Slow Services ──────────────────────────
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown(section_header_html("Top Threats", "", "🔥"), unsafe_allow_html=True)
        if security_results:
            bf = security_results.get("brute_force", None)
            if bf is not None and not bf.empty:
                for _, row in bf.head(5).iterrows():
                    severity_color = "#ef4444" if row.get("severity") == "CRITICAL" else "#f59e0b"
                    st.markdown(f"""<div style="background:#1a1f2e; border:1px solid #1e293b; border-left:3px solid {severity_color};
                        border-radius:8px; padding:10px 14px; margin-bottom:6px; font-size:0.82rem; color:#cbd5e1;
                        transition:all 0.2s;" onmouseover="this.style.borderLeftColor='{severity_color}'; this.style.background='#242b3d'"
                        onmouseout="this.style.background='#1a1f2e'">
                        🔓 <b>{row.get('ip_address','N/A')}</b> — {row.get('attempt_count',0)} attempts
                        <span style="float:right;color:{severity_color};font-size:0.7rem;font-weight:600">{row.get('severity','')}</span>
                    </div>""", unsafe_allow_html=True)
            else:
                st.markdown("<div style='color:#64748b; padding:20px; text-align:center;'>No threats detected ✅</div>", unsafe_allow_html=True)

    with col_b:
        st.markdown(section_header_html("Slowest Services", "", "🐌"), unsafe_allow_html=True)
        if performance_results and "latency_percentiles" in performance_results:
            lp = performance_results["latency_percentiles"]
            if not lp.empty:
                slow = lp.sort_values("p95", ascending=False).head(5)
                for _, row in slow.iterrows():
                    p95_color = "#ef4444" if row["p95"] > 500 else ("#f59e0b" if row["p95"] > 200 else "#10b981")
                    st.markdown(f"""<div style="background:#1a1f2e; border:1px solid #1e293b; border-left:3px solid {p95_color};
                        border-radius:8px; padding:10px 14px; margin-bottom:6px; font-size:0.82rem; color:#cbd5e1;
                        transition:all 0.2s;" onmouseover="this.style.background='#242b3d'" onmouseout="this.style.background='#1a1f2e'">
                        ⚡ <b>{row['service']}</b> — p95: {row['p95']:.0f}ms
                        <span style="float:right;color:{p95_color};font-size:0.7rem;font-weight:600">p99: {row['p99']:.0f}ms</span>
                    </div>""", unsafe_allow_html=True)

    # ─── Risk Distribution ────────────────────────────────────
    if risk_summary and risk_summary.get("total_users_scored", 0) > 0:
        st.markdown("---")
        st.markdown(section_header_html("Risk Overview", "", "⚠️"), unsafe_allow_html=True)
        rc1, rc2, rc3, rc4 = st.columns(4)
        dist = risk_summary.get("user_risk_distribution", {})
        with rc1:
            st.markdown(kpi_card_html("Low Risk", str(dist.get("Low", 0)), "Score 0-25", "🟢", accent_color="#10b981"), unsafe_allow_html=True)
        with rc2:
            st.markdown(kpi_card_html("Medium Risk", str(dist.get("Medium", 0)), "Score 26-50", "🟡", accent_color="#f59e0b"), unsafe_allow_html=True)
        with rc3:
            st.markdown(kpi_card_html("High Risk", str(dist.get("High", 0)), "Score 51-75", "🟠", accent_color="#f97316"), unsafe_allow_html=True)
        with rc4:
            st.markdown(kpi_card_html("Critical", str(dist.get("Critical", 0)), "Score 76-100", "🔴", accent_color="#ef4444"), unsafe_allow_html=True)
