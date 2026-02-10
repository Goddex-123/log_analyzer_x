"""
Log Analyzer X – Performance & SRE Page
"""
import streamlit as st
from utils.helpers import section_header_html, kpi_card_html, rag_badge_html, alert_card_html
from visualization.charts import (latency_distribution, throughput_chart, service_health_gauge,
                                   latency_percentiles_chart, trend_line_chart, anomaly_timeline)


def render(df, performance_results, anomaly_results, forecasting_results):
    st.markdown(section_header_html("Performance & SRE Intelligence", "Latency, SLA, throughput & anomaly analysis", "⚡"), unsafe_allow_html=True)

    if not performance_results:
        st.info("Run analysis to view performance data.")
        return

    # KPIs
    c1, c2, c3, c4 = st.columns(4)
    health = performance_results.get("overall_health_score", 0)
    sla_breaches = performance_results.get("services_breaching_sla", 0)
    lat_spikes = anomaly_results.get("total_latency_spikes", 0) if anomaly_results else 0

    with c1:
        color = "#10b981" if health >= 85 else ("#f59e0b" if health >= 60 else "#ef4444")
        st.markdown(kpi_card_html("System Health", f"{health:.0f}/100", "", "💚", accent_color=color), unsafe_allow_html=True)
    with c2:
        st.markdown(kpi_card_html("SLA Breaches", str(sla_breaches), "", "📉",
                                  accent_color="#ef4444" if sla_breaches > 0 else "#10b981"), unsafe_allow_html=True)
    with c3:
        st.markdown(kpi_card_html("Latency Spikes", str(lat_spikes), "", "🔺",
                                  accent_color="#f59e0b"), unsafe_allow_html=True)
    with c4:
        bottlenecks = len(performance_results.get("bottlenecks", []))
        st.markdown(kpi_card_html("Bottlenecks", str(bottlenecks), "", "🔧",
                                  accent_color="#ef4444" if bottlenecks > 0 else "#10b981"), unsafe_allow_html=True)

    st.markdown("---")
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["🏥 Service Health", "📊 Latency", "⚡ Throughput", "🔺 Anomalies", "📈 Trends"])

    with tab1:
        health_df = performance_results.get("service_health", None)
        if health_df is not None and not health_df.empty:
            st.plotly_chart(service_health_gauge(health_df), use_container_width=True)
            # RAG table
            st.markdown("##### Service Status Matrix")
            for _, row in health_df.iterrows():
                rag = row.get("rag_status", "GREEN")
                st.markdown(f"""<div style="display:flex;align-items:center;gap:12px;background:#1a1f2e;
                    border:1px solid #1e293b;border-radius:8px;padding:10px 16px;margin-bottom:6px;">
                    <span style="flex:1;color:#f1f5f9;font-weight:600;">{row['service']}</span>
                    {rag_badge_html(rag)}
                    <span style="color:#94a3b8;font-size:0.8rem;">Health: {row['health_score']:.0f}</span>
                    <span style="color:#64748b;font-size:0.75rem;">Err: {row['error_rate']*100:.1f}%</span>
                </div>""", unsafe_allow_html=True)

    with tab2:
        st.plotly_chart(latency_distribution(df), use_container_width=True)
        lp = performance_results.get("latency_percentiles", None)
        if lp is not None and not lp.empty:
            st.plotly_chart(latency_percentiles_chart(lp), use_container_width=True)
            st.dataframe(lp, use_container_width=True, hide_index=True)

    with tab3:
        tp = performance_results.get("throughput", None)
        if tp is not None and not tp.empty:
            st.plotly_chart(throughput_chart(tp), use_container_width=True)

    with tab4:
        if anomaly_results:
            ls = anomaly_results.get("latency_spikes", None)
            if ls is not None and not ls.empty:
                st.plotly_chart(anomaly_timeline(ls), use_container_width=True)
                st.dataframe(ls.head(20), use_container_width=True, hide_index=True)
            else:
                st.success("No latency anomalies detected.")
        # Bottleneck hints
        bns = performance_results.get("bottlenecks", [])
        if bns:
            st.markdown("##### 🔧 Bottleneck Root Cause Hints")
            for bn in bns:
                st.markdown(alert_card_html(bn["type"], bn["detail"], bn["severity"],
                                            f"Service: {bn['service']}", ""), unsafe_allow_html=True)

    with tab5:
        if forecasting_results:
            hourly = forecasting_results.get("hourly_latency", None)
            if hourly is not None and not hourly.empty:
                st.plotly_chart(trend_line_chart(hourly, "Latency Trend with Moving Averages"), use_container_width=True)
            trend = forecasting_results.get("latency_trend", {})
            if trend:
                st.markdown(f"""<div style="background:#1a1f2e;border:1px solid #1e293b;border-radius:10px;padding:16px;">
                    <div style="color:#94a3b8;font-size:0.8rem;">LATENCY TREND</div>
                    <div style="color:#f1f5f9;font-size:1.1rem;font-weight:600;margin-top:4px;">
                        Direction: <span style="color:{'#ef4444' if trend.get('trend')=='increasing' else '#10b981'}">{trend.get('trend','stable').upper()}</span>
                    </div>
                    <div style="color:#64748b;font-size:0.75rem;margin-top:4px;">
                        Slope: {trend.get('slope',0):.4f} | R²: {trend.get('r_squared',0):.4f}
                    </div>
                </div>""", unsafe_allow_html=True)

    # SLA Breaches detail
    sla_df = performance_results.get("sla_breaches", None)
    if sla_df is not None and not sla_df.empty:
        st.markdown("---")
        st.markdown(section_header_html("SLA Breach Details", "", "🚨"), unsafe_allow_html=True)
        st.dataframe(sla_df, use_container_width=True, hide_index=True)
