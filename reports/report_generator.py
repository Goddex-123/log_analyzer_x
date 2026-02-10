"""
Log Analyzer X – Report Generator
Generates HTML reports for security audits, SLA compliance, and executive summaries.
Downloadable via Streamlit.
"""

import pandas as pd
from datetime import datetime
from config.settings import APP_NAME, COLORS


def _html_header(title: str, subtitle: str = "") -> str:
    """Generate HTML report header."""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>{title} | {APP_NAME}</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: 'Segoe UI', -apple-system, sans-serif;
                background: {COLORS['bg_primary']}; color: {COLORS['text_primary']};
                padding: 40px; line-height: 1.6;
            }}
            .header {{
                background: linear-gradient(135deg, #1a1f2e, #111827);
                border: 1px solid {COLORS['border']};
                border-radius: 12px; padding: 30px 40px; margin-bottom: 30px;
                border-left: 4px solid {COLORS['accent_blue']};
            }}
            .header h1 {{ font-size: 1.8rem; color: {COLORS['text_primary']}; }}
            .header .subtitle {{ color: {COLORS['text_secondary']}; font-size: 0.9rem; margin-top: 5px; }}
            .header .meta {{ color: {COLORS['text_muted']}; font-size: 0.75rem; margin-top: 10px; }}
            .section {{
                background: {COLORS['bg_card']}; border: 1px solid {COLORS['border']};
                border-radius: 10px; padding: 24px; margin-bottom: 20px;
            }}
            .section h2 {{
                font-size: 1.2rem; color: {COLORS['accent_blue']};
                margin-bottom: 15px; padding-bottom: 8px;
                border-bottom: 1px solid {COLORS['border']};
            }}
            table {{
                width: 100%; border-collapse: collapse; margin: 10px 0;
                font-size: 0.85rem;
            }}
            th {{
                background: {COLORS['bg_secondary']}; color: {COLORS['text_secondary']};
                padding: 10px 12px; text-align: left; font-weight: 600;
                text-transform: uppercase; font-size: 0.7rem; letter-spacing: 1px;
            }}
            td {{ padding: 10px 12px; border-bottom: 1px solid {COLORS['border']}; }}
            tr:hover td {{ background: {COLORS['bg_card_hover']}; }}
            .kpi-row {{ display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }}
            .kpi-card {{
                flex: 1; min-width: 160px; background: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border']}; border-radius: 8px;
                padding: 16px; text-align: center;
            }}
            .kpi-card .value {{ font-size: 1.6rem; font-weight: 700; color: {COLORS['text_primary']}; }}
            .kpi-card .label {{ font-size: 0.7rem; color: {COLORS['text_muted']}; text-transform: uppercase; }}
            .badge {{
                display: inline-block; padding: 2px 8px; border-radius: 12px;
                font-size: 0.7rem; font-weight: 600;
            }}
            .badge-critical {{ background: {COLORS['accent_red']}22; color: {COLORS['accent_red']}; }}
            .badge-warning {{ background: {COLORS['accent_amber']}22; color: {COLORS['accent_amber']}; }}
            .badge-info {{ background: {COLORS['accent_blue']}22; color: {COLORS['accent_blue']}; }}
            .badge-success {{ background: {COLORS['accent_green']}22; color: {COLORS['accent_green']}; }}
            .footer {{
                text-align: center; color: {COLORS['text_muted']}; font-size: 0.7rem;
                margin-top: 40px; padding-top: 20px; border-top: 1px solid {COLORS['border']};
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>{title}</h1>
            <div class="subtitle">{subtitle}</div>
            <div class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {APP_NAME} v1.0</div>
        </div>
    """


def _html_footer() -> str:
    return f"""
        <div class="footer">
            {APP_NAME} – Enterprise Security & Performance Intelligence Platform<br>
            This report is auto-generated. For questions, contact your SOC team.
        </div>
    </body>
    </html>
    """


def _kpi_html(label: str, value: str, color: str = "") -> str:
    val_style = f"color: {color};" if color else ""
    return f"""
    <div class="kpi-card">
        <div class="value" style="{val_style}">{value}</div>
        <div class="label">{label}</div>
    </div>
    """


def _df_to_html_table(df: pd.DataFrame, max_rows: int = 50) -> str:
    """Convert a DataFrame to a styled HTML table."""
    if df.empty:
        return "<p style='color: #64748b;'>No data available.</p>"
    display_df = df.head(max_rows)
    return display_df.to_html(index=False, border=0, classes="report-table")


def generate_security_report(security_results: dict, risk_results: dict = None,
                              alert_summary: dict = None) -> str:
    """Generate a comprehensive security audit report."""
    html = _html_header("Security Audit Report",
                        "Comprehensive security analysis and threat assessment")

    # KPIs
    html += '<div class="section"><h2>🔐 Security Overview</h2><div class="kpi-row">'
    html += _kpi_html("Total Threats", str(security_results.get("total_threats", 0)), COLORS["accent_red"])
    html += _kpi_html("Risk Index", f"{security_results.get('risk_index', 0)}/100", COLORS["accent_amber"])
    html += _kpi_html("High-Risk IPs", str(security_results.get("high_risk_ips", 0)), COLORS["accent_red"])
    html += _kpi_html("Failure Rate", f"{security_results.get('failure_rate', 0)}%", COLORS["accent_amber"])
    html += '</div></div>'

    # Brute Force
    bf = security_results.get("brute_force", pd.DataFrame())
    if not bf.empty:
        html += '<div class="section"><h2>🔓 Brute Force Detections</h2>'
        display_bf = bf[["ip_address", "timestamp", "attempt_count", "severity", "country"]].head(20) if len(bf.columns) > 0 else bf.head(20)
        html += _df_to_html_table(display_bf)
        html += '</div>'

    # Credential Stuffing
    cs = security_results.get("credential_stuffing", pd.DataFrame())
    if not cs.empty:
        html += '<div class="section"><h2>🔑 Credential Stuffing Detections</h2>'
        display_cs = cs[["ip_address", "timestamp", "unique_users_targeted", "total_attempts", "severity"]].head(20) if len(cs.columns) > 0 else cs.head(20)
        html += _df_to_html_table(display_cs)
        html += '</div>'

    # MITRE Mapping
    mitre = security_results.get("mitre_mapping", pd.DataFrame())
    if not mitre.empty:
        html += '<div class="section"><h2>🎯 MITRE ATT&CK Mapping</h2>'
        html += _df_to_html_table(mitre.head(20))
        html += '</div>'

    # IP Reputation
    ip_rep = security_results.get("ip_reputation", pd.DataFrame())
    if not ip_rep.empty:
        html += '<div class="section"><h2>🌐 IP Reputation (Top 20 Riskiest)</h2>'
        html += _df_to_html_table(ip_rep.head(20))
        html += '</div>'

    html += _html_footer()
    return html


def generate_sla_report(performance_results: dict) -> str:
    """Generate SLA compliance report."""
    html = _html_header("SLA Compliance Report",
                        "Service Level Agreement monitoring and breach analysis")

    # KPIs
    html += '<div class="section"><h2>⚡ Performance Overview</h2><div class="kpi-row">'
    html += _kpi_html("System Health", f"{performance_results.get('overall_health_score', 0)}/100",
                      COLORS["accent_green"] if performance_results.get("overall_health_score", 0) > 80 else COLORS["accent_red"])
    html += _kpi_html("SLA Breaches", str(performance_results.get("services_breaching_sla", 0)), COLORS["accent_red"])
    html += '</div></div>'

    # Service Health
    health = performance_results.get("service_health", pd.DataFrame())
    if not health.empty:
        html += '<div class="section"><h2>🏥 Service Health Matrix</h2>'
        html += _df_to_html_table(health)
        html += '</div>'

    # SLA Breaches
    sla = performance_results.get("sla_breaches", pd.DataFrame())
    if not sla.empty:
        html += '<div class="section"><h2>🚨 SLA Breaches</h2>'
        html += _df_to_html_table(sla)
        html += '</div>'

    # Latency Percentiles
    latency = performance_results.get("latency_percentiles", pd.DataFrame())
    if not latency.empty:
        html += '<div class="section"><h2>📊 Latency Percentiles by Service</h2>'
        html += _df_to_html_table(latency)
        html += '</div>'

    html += _html_footer()
    return html


def generate_executive_summary(security_results: dict, performance_results: dict,
                                alert_summary: dict = None, usage_results: dict = None) -> str:
    """Generate a 1-page executive summary."""
    html = _html_header("Executive Summary",
                        "High-level intelligence briefing for leadership")

    risk_idx = security_results.get("risk_index", 0) if security_results else 0
    health = performance_results.get("overall_health_score", 0) if performance_results else 0
    total_alerts = alert_summary.get("total", 0) if alert_summary else 0
    critical_alerts = alert_summary.get("critical", 0) if alert_summary else 0

    html += '<div class="section"><h2>📊 Key Performance Indicators</h2><div class="kpi-row">'
    html += _kpi_html("Security Risk Index", f"{risk_idx}/100",
                      COLORS["accent_green"] if risk_idx < 30 else COLORS["accent_red"])
    html += _kpi_html("System Health", f"{health}/100",
                      COLORS["accent_green"] if health > 80 else COLORS["accent_red"])
    html += _kpi_html("Active Alerts", str(total_alerts),
                      COLORS["accent_amber"] if total_alerts > 0 else COLORS["accent_green"])
    html += _kpi_html("Critical Alerts", str(critical_alerts), COLORS["accent_red"])
    html += '</div></div>'

    # Top Threats
    if security_results:
        html += '<div class="section"><h2>🔐 Security Summary</h2>'
        html += f"<p>Total threats detected: <strong>{security_results.get('total_threats', 0)}</strong></p>"
        html += f"<p>High-risk IPs: <strong>{security_results.get('high_risk_ips', 0)}</strong></p>"
        html += f"<p>Authentication failure rate: <strong>{security_results.get('failure_rate', 0)}%</strong></p>"
        html += '</div>'

    # Performance
    if performance_results:
        html += '<div class="section"><h2>⚡ Performance Summary</h2>'
        html += f"<p>Overall health score: <strong>{health}/100</strong></p>"
        html += f"<p>Services breaching SLA: <strong>{performance_results.get('services_breaching_sla', 0)}</strong></p>"
        html += '</div>'

    # Usage
    if usage_results:
        html += '<div class="section"><h2>👥 Usage Summary</h2>'
        html += f"<p>Total users analyzed: <strong>{usage_results.get('total_users', 0)}</strong></p>"
        html += f"<p>Suspicious users flagged: <strong>{usage_results.get('suspicious_users', 0)}</strong></p>"
        html += '</div>'

    html += _html_footer()
    return html
