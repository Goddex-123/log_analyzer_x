"""
Log Analyzer X – Main Application
Enterprise Security & Performance Intelligence Platform
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st
import pandas as pd

# ─── Page Config (must be first Streamlit call) ───────────────
st.set_page_config(
    page_title="Log Analyzer X",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Inject Custom CSS ───────────────────────────────────────
from config.theme import CUSTOM_CSS
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ─── Imports ──────────────────────────────────────────────────
from config.settings import APP_NAME, APP_SUBTITLE, PAGES
from ingestion.file_handler import render_upload_widget, auto_map_columns
from preprocessing.data_cleaner import clean_and_normalize, get_data_quality_report
from analytics.security import run_security_analysis
from analytics.usage import run_usage_analysis
from analytics.performance import run_performance_analysis
from analytics.anomaly import run_anomaly_analysis
from analytics.forecasting import run_forecasting_analysis
from ml.isolation_forest import run_isolation_forest
from ml.behavior_clustering import run_kmeans_clustering, run_dbscan_clustering
from ml.risk_scoring import calculate_user_risk_scores, calculate_ip_risk_scores, get_risk_summary
from alerts.alert_engine import generate_alerts, get_alert_summary
from utils.helpers import section_header_html


# ─── Sidebar ─────────────────────────────────────────────────
with st.sidebar:
    st.markdown(f"""
    <div style="text-align:center; padding:20px 10px 10px;">
        <div style="font-size:2.2rem; margin-bottom:4px;">🛡️</div>
        <div style="background:linear-gradient(135deg,#3b82f6,#8b5cf6);-webkit-background-clip:text;
            -webkit-text-fill-color:transparent;font-weight:800;font-size:1.3rem;">{APP_NAME}</div>
        <div style="color:#64748b;font-size:0.65rem;letter-spacing:1.5px;text-transform:uppercase;margin-top:2px;">
            {APP_SUBTITLE}
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("<div style='color:#94a3b8;font-size:0.7rem;text-transform:uppercase;letter-spacing:1.5px;padding:0 16px;margin-bottom:8px;'>Navigation</div>", unsafe_allow_html=True)

    page_options = [f"{v['icon']} {v['label']}" for v in PAGES.values()]
    selected_page = st.radio("", page_options, label_visibility="collapsed")
    page_key = list(PAGES.keys())[page_options.index(selected_page)]

    st.markdown("---")

    # Data upload in sidebar
    st.markdown("<div style='color:#94a3b8;font-size:0.7rem;text-transform:uppercase;letter-spacing:1.5px;padding:0 16px;margin-bottom:8px;'>Data Source</div>", unsafe_allow_html=True)
    df_raw, validation_report = render_upload_widget()

    if df_raw is not None and validation_report is not None:
        st.success(f"✅ {validation_report['total_rows']:,} rows loaded")
        st.session_state["df_raw"] = df_raw
        st.session_state["validation_report"] = validation_report
        st.rerun()

    elif "df_raw" not in st.session_state:
        st.markdown("""<div style="background:#1a1f2e;border:1px solid #1e293b;border-radius:8px;padding:14px;text-align:center;margin-bottom:10px;">
            <div style="color:#64748b;font-size:0.8rem;">Upload a CSV log file to begin analysis</div>
        </div>""", unsafe_allow_html=True)
        
        if st.button("🎲 Generate Sample Data", use_container_width=True):
            from generate_sample_data import generate_logs, OUTPUT_FILE
            with st.spinner("Generating 50,000+ log records with attack patterns..."):
                generate_logs()
                
            # Load the generated file
            with st.spinner("Loading and validating data..."):
                try:
                    generated_df = pd.read_csv(OUTPUT_FILE)
                    # We need to run the upload widget's validation logic manually here
                    # effectively simulating a file upload
                    from ingestion.file_handler import validate_upload
                    report = validate_upload(generated_df)
                    
                    st.session_state["df_raw"] = generated_df
                    st.session_state["validation_report"] = report
                    st.success("Sample data generated and loaded!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error loading sample data: {e}")

    st.markdown("---")
    st.markdown(f"""<div style="text-align:center;color:#334155;font-size:0.6rem;padding:10px;">
        v1.0.0 · Built with Streamlit
    </div>""", unsafe_allow_html=True)


# ─── Main Content ────────────────────────────────────────────
if "df_raw" not in st.session_state:
    # Landing page
    st.markdown(f"""
    <div style="text-align:center; padding:80px 20px 40px;">
        <div style="font-size:4rem; margin-bottom:16px;">🛡️</div>
        <h1 style="font-size:2.5rem!important; margin-bottom:8px;">{APP_NAME}</h1>
        <div style="color:#94a3b8; font-size:1.1rem; max-width:600px; margin:0 auto 40px;">
            {APP_SUBTITLE}
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Feature cards
    features = [
        ("🔐", "Security Intelligence", "Brute force detection, credential stuffing, IP reputation, MITRE ATT&CK mapping"),
        ("⚡", "Performance & SRE", "Latency percentiles, SLA breaches, throughput analysis, service health scoring"),
        ("🤖", "Machine Learning", "Isolation Forest anomaly detection, behavior clustering, composite risk scoring"),
        ("🚨", "Smart Alerting", "Rule-based alerts, severity classification, real-time monitoring, CSV export"),
        ("📊", "Executive Dashboards", "C-level KPIs, trend analysis, system health overview, risk distribution"),
        ("📝", "Audit Reports", "Security audit, SLA compliance, executive summary — all downloadable"),
    ]
    cols = st.columns(3)
    for i, (icon, title, desc) in enumerate(features):
        with cols[i % 3]:
            st.markdown(f"""<div style="background:linear-gradient(145deg,#1a1f2e,#111827);border:1px solid #1e293b;
                border-radius:12px;padding:24px;margin-bottom:16px;text-align:center;min-height:170px;
                transition:all 0.3s ease;" onmouseover="this.style.transform='translateY(-4px)';this.style.boxShadow='0 8px 30px rgba(59,130,246,0.12)'"
                onmouseout="this.style.transform='';this.style.boxShadow=''">
                <div style="font-size:2rem;margin-bottom:10px;">{icon}</div>
                <div style="color:#f1f5f9;font-weight:700;font-size:0.95rem;margin-bottom:6px;">{title}</div>
                <div style="color:#64748b;font-size:0.75rem;">{desc}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("""<div style="text-align:center;color:#64748b;font-size:0.8rem;margin-top:30px;">
        Upload a CSV file in the sidebar to begin analysis · Supports files up to 100MB
    </div>""", unsafe_allow_html=True)
    st.stop()


# ─── Data Processing ─────────────────────────────────────────
@st.cache_data(show_spinner=False)
def process_data(df_raw_json, mapping):
    df = pd.read_json(df_raw_json)
    return clean_and_normalize(df, mapping)

validation_report = st.session_state["validation_report"]
mapping = validation_report.get("column_mapping", {})

# Cache the cleaned data
cache_key = f"df_clean_{len(st.session_state['df_raw'])}"
if cache_key not in st.session_state:
    with st.spinner("Cleaning and normalizing data..."):
        st.session_state[cache_key] = clean_and_normalize(st.session_state["df_raw"], mapping)
df = st.session_state[cache_key]


# ─── Run All Analysis Pipelines ──────────────────────────────
@st.cache_data(show_spinner=False)
def run_all_analysis(_df_json, n_rows):
    """Run all analysis pipelines. Uses n_rows as cache key proxy."""
    _df = pd.read_json(_df_json)
    security = run_security_analysis(_df)
    usage = run_usage_analysis(_df)
    performance = run_performance_analysis(_df)
    anomaly = run_anomaly_analysis(_df)
    forecasting = run_forecasting_analysis(_df)

    ml = {
        "isolation_forest": run_isolation_forest(_df),
        "kmeans": run_kmeans_clustering(_df),
        "dbscan": run_dbscan_clustering(_df),
    }

    user_risks = calculate_user_risk_scores(_df, security, ml)
    ip_risks = calculate_ip_risk_scores(_df, security)
    risk_summary = get_risk_summary(user_risks, ip_risks)

    alerts = generate_alerts(_df, security, performance, anomaly, risk_summary)
    alert_sum = get_alert_summary(alerts)

    return {
        "security": security, "usage": usage, "performance": performance,
        "anomaly": anomaly, "forecasting": forecasting, "ml": ml,
        "user_risks": user_risks, "ip_risks": ip_risks, "risk_summary": risk_summary,
        "alerts": alerts, "alert_summary": alert_sum,
    }

analysis_key = f"analysis_{len(df)}"
if analysis_key not in st.session_state:
    with st.spinner("🔍 Running security, performance, ML analysis pipelines..."):
        try:
            df_json = df.to_json()
            st.session_state[analysis_key] = run_all_analysis(df_json, len(df))
        except Exception as e:
            st.error(f"Analysis error: {e}")
            st.stop()

results = st.session_state[analysis_key]


# ─── Page Routing ─────────────────────────────────────────────
from pages.executive import render as render_executive
from pages.security_page import render as render_security
from pages.performance_page import render as render_performance
from pages.ml_page import render as render_ml
from pages.alerts_page import render as render_alerts
from pages.reports_page import render as render_reports

if page_key == "executive":
    render_executive(df, results["security"], results["performance"], results["usage"],
                     results["anomaly"], results["alert_summary"], results["risk_summary"])
elif page_key == "security":
    render_security(df, results["security"])
elif page_key == "performance":
    render_performance(df, results["performance"], results["anomaly"], results["forecasting"])
elif page_key == "ml_insights":
    render_ml(df, results["ml"], {"user_risks": results["user_risks"], "ip_risks": results["ip_risks"]})
elif page_key == "alerts":
    render_alerts(results["alerts"], results["alert_summary"])
elif page_key == "reports":
    render_reports(results["security"], results["performance"], results["usage"], results["alert_summary"])
