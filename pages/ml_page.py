"""
Log Analyzer X – ML Insights Page
"""
import streamlit as st
from utils.helpers import section_header_html, kpi_card_html
from visualization.charts import anomaly_scatter, cluster_scatter, risk_distribution_chart


def render(df, ml_results, risk_data):
    st.markdown(section_header_html("ML Insights", "Machine learning anomaly detection, clustering & risk scoring", "🤖"), unsafe_allow_html=True)

    if not ml_results:
        st.info("Run analysis to view ML insights.")
        return

    tab1, tab2, tab3, tab4 = st.tabs(["🔍 Isolation Forest", "🧠 Behavior Clusters", "⚠️ Risk Scores", "📖 Model Docs"])

    # ─── Isolation Forest ─────────────────────────────────────
    with tab1:
        if_data = ml_results.get("isolation_forest", {})
        if_results = if_data.get("results", None)
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(kpi_card_html("Anomalies", str(if_data.get("anomaly_count", 0)), "", "🔴", accent_color="#ef4444"), unsafe_allow_html=True)
        with c2:
            st.markdown(kpi_card_html("Sessions", str(if_data.get("total_sessions", 0)), "", "📊", accent_color="#3b82f6"), unsafe_allow_html=True)
        with c3:
            st.markdown(kpi_card_html("Anomaly Rate", f"{if_data.get('anomaly_rate', 0)}%", "", "📈", accent_color="#f59e0b"), unsafe_allow_html=True)

        if if_results is not None and not if_results.empty:
            st.plotly_chart(anomaly_scatter(if_results), use_container_width=True)
            with st.expander("View Anomalous Sessions"):
                anomalies = if_results[if_results["is_anomaly"] == True]
                if not anomalies.empty:
                    display_cols = [c for c in ["session_id","request_count","error_rate","avg_latency","max_latency","anomaly_score"] if c in anomalies.columns]
                    st.dataframe(anomalies[display_cols].head(30), use_container_width=True, hide_index=True)

    # ─── Behavior Clusters ────────────────────────────────────
    with tab2:
        km_data = ml_results.get("kmeans", {})
        km_results = km_data.get("results", None)
        profiles = km_data.get("cluster_profiles", {})

        if km_results is not None and not km_results.empty:
            st.plotly_chart(cluster_scatter(km_results), use_container_width=True)
            st.markdown(f"**Silhouette Score:** `{km_data.get('silhouette_score', 0):.4f}` (higher is better, >0.5 = well-defined)")
            st.markdown("##### Cluster Profiles")
            cols = st.columns(min(len(profiles), 4))
            for i, (cid, prof) in enumerate(profiles.items()):
                with cols[i % len(cols)]:
                    st.markdown(f"""<div style="background:#1a1f2e;border:1px solid #1e293b;border-radius:10px;padding:14px;text-align:center;">
                        <div style="font-size:1.1rem;margin-bottom:6px;">{prof['label']}</div>
                        <div style="color:#94a3b8;font-size:0.75rem;">{prof['size']} users</div>
                        <div style="color:#64748b;font-size:0.7rem;margin-top:6px;">
                            Avg requests: {prof['avg_requests']}<br>
                            Failure rate: {prof['avg_failure_rate']}%<br>
                            Avg latency: {prof['avg_latency']}ms
                        </div>
                    </div>""", unsafe_allow_html=True)

        db_data = ml_results.get("dbscan", {})
        if db_data.get("noise_count", 0) > 0:
            st.markdown("---")
            st.markdown(f"##### DBSCAN Outlier Detection")
            st.markdown(f"**{db_data['noise_count']}** noise/outlier users detected (don't fit any behavior cluster)")

    # ─── Risk Scores ──────────────────────────────────────────
    with tab3:
        user_risks = risk_data.get("user_risks", None) if risk_data else None
        if user_risks is not None and not user_risks.empty:
            st.plotly_chart(risk_distribution_chart(user_risks), use_container_width=True)
            st.markdown("##### Highest Risk Users")
            display_cols = [c for c in ["user_id","risk_score","risk_tier","failure_rate","unique_ips","unique_countries"] if c in user_risks.columns]
            st.dataframe(user_risks[display_cols].head(20), use_container_width=True, hide_index=True)
        else:
            st.info("No risk score data available.")

    # ─── Model Documentation ─────────────────────────────────
    with tab4:
        for name, data in [("Isolation Forest", ml_results.get("isolation_forest",{})),
                           ("KMeans Clustering", ml_results.get("kmeans",{})),
                           ("DBSCAN", ml_results.get("dbscan",{}))]:
            info = data.get("model_info", {})
            if isinstance(info, dict) and info:
                st.markdown(f"""<div style="background:#1a1f2e;border:1px solid #1e293b;border-left:3px solid #3b82f6;
                    border-radius:10px;padding:18px;margin-bottom:12px;">
                    <div style="color:#3b82f6;font-weight:700;font-size:1rem;margin-bottom:8px;">{name}</div>
                    <div style="color:#94a3b8;font-size:0.82rem;"><b>Algorithm:</b> {info.get('algorithm','')}</div>
                    <div style="color:#94a3b8;font-size:0.82rem;margin-top:6px;"><b>Why Chosen:</b> {info.get('why_chosen','')}</div>
                    <div style="color:#94a3b8;font-size:0.82rem;margin-top:6px;"><b>Features:</b> {', '.join(info.get('features_used', []))}</div>
                    <div style="color:#64748b;font-size:0.78rem;margin-top:6px;"><b>Interpretation:</b> {info.get('interpretation','')}</div>
                </div>""", unsafe_allow_html=True)
            elif isinstance(info, str):
                st.info(info)
