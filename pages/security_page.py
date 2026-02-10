"""
Log Analyzer X – Security Intelligence Page
"""
import streamlit as st
import pandas as pd
from utils.helpers import section_header_html, kpi_card_html, format_number
from visualization.charts import attack_timeline_chart, login_heatmap, ip_risk_distribution


def render(df, security_results):
    st.markdown(section_header_html("Security Intelligence", "Threat detection, IP reputation & MITRE ATT&CK mapping", "🔐"), unsafe_allow_html=True)

    if not security_results:
        st.info("Run analysis to view security intelligence.")
        return

    # KPIs
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(kpi_card_html("Risk Index", f"{security_results.get('risk_index',0)}/100", "", "🎯",
                                  accent_color="#ef4444"), unsafe_allow_html=True)
    with c2:
        st.markdown(kpi_card_html("Total Threats", str(security_results.get("total_threats",0)), "", "🔥",
                                  accent_color="#f59e0b"), unsafe_allow_html=True)
    with c3:
        st.markdown(kpi_card_html("High-Risk IPs", str(security_results.get("high_risk_ips",0)), "", "🌐",
                                  accent_color="#ef4444"), unsafe_allow_html=True)
    with c4:
        st.markdown(kpi_card_html("Failure Rate", f"{security_results.get('failure_rate',0)}%", "", "⚡",
                                  accent_color="#f59e0b"), unsafe_allow_html=True)

    st.markdown("---")

    # Tabs for different security views
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["🔓 Attack Timeline", "🔥 Login Heatmap", "🌐 IP Reputation", "🗺️ Geo Anomalies", "🎯 MITRE ATT&CK"])

    with tab1:
        bf = security_results.get("brute_force", pd.DataFrame())
        cs = security_results.get("credential_stuffing", pd.DataFrame())
        fig = attack_timeline_chart(bf, cs)
        st.plotly_chart(fig, use_container_width=True)

        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("##### 🔓 Brute Force Detections")
            if not bf.empty:
                display_cols = [c for c in ["ip_address","timestamp","attempt_count","severity","country"] if c in bf.columns]
                st.dataframe(bf[display_cols].head(20), use_container_width=True, hide_index=True)
            else:
                st.success("No brute force attacks detected.")
        with col_b:
            st.markdown("##### 🔑 Credential Stuffing")
            if not cs.empty:
                display_cols = [c for c in ["ip_address","timestamp","unique_users_targeted","total_attempts","severity"] if c in cs.columns]
                st.dataframe(cs[display_cols].head(20), use_container_width=True, hide_index=True)
            else:
                st.success("No credential stuffing detected.")

    with tab2:
        fig = login_heatmap(df)
        st.plotly_chart(fig, use_container_width=True)

    with tab3:
        ip_rep = security_results.get("ip_reputation", pd.DataFrame())
        if not ip_rep.empty:
            fig = ip_risk_distribution(ip_rep)
            st.plotly_chart(fig, use_container_width=True)
            st.markdown("##### Top 20 Riskiest IPs")
            st.dataframe(ip_rep.head(20), use_container_width=True, hide_index=True)
        else:
            st.info("No IP reputation data.")

    with tab4:
        geo = security_results.get("geo_anomalies", pd.DataFrame())
        if not geo.empty:
            st.warning(f"⚠️ {len(geo)} users accessing from unusual geographic locations")
            st.dataframe(geo.head(20), use_container_width=True, hide_index=True)
        else:
            st.success("No geo-location anomalies.")

    with tab5:
        mitre = security_results.get("mitre_mapping", pd.DataFrame())
        if not mitre.empty:
            st.dataframe(mitre, use_container_width=True, hide_index=True)
        else:
            st.info("No MITRE ATT&CK techniques mapped.")

        # Show reference table
        with st.expander("📖 MITRE ATT&CK Reference"):
            from config.settings import MITRE_MAPPING
            for key, info in MITRE_MAPPING.items():
                st.markdown(f"""<div style="background:#1a1f2e;border:1px solid #1e293b;border-radius:8px;padding:12px;margin-bottom:8px;">
                    <div style="color:#3b82f6;font-weight:700;">{info['technique_id']} — {info['technique_name']}</div>
                    <div style="color:#94a3b8;font-size:0.8rem;">Tactic: {info['tactic']}</div>
                    <div style="color:#64748b;font-size:0.75rem;margin-top:4px;">{info['description']}</div>
                </div>""", unsafe_allow_html=True)
