"""
Log Analyzer X – Shared Utilities
Common helper functions used across the platform.
"""

import hashlib
import pandas as pd
import numpy as np
from datetime import datetime


def format_number(n: float, decimals: int = 1) -> str:
    """Format large numbers with K/M/B suffixes."""
    if abs(n) >= 1_000_000_000:
        return f"{n / 1_000_000_000:.{decimals}f}B"
    elif abs(n) >= 1_000_000:
        return f"{n / 1_000_000:.{decimals}f}M"
    elif abs(n) >= 1_000:
        return f"{n / 1_000:.{decimals}f}K"
    else:
        return f"{n:.{decimals}f}" if decimals > 0 else str(int(n))


def format_latency(ms: float) -> str:
    """Format latency in ms with appropriate units."""
    if ms >= 1000:
        return f"{ms / 1000:.2f}s"
    return f"{ms:.1f}ms"


def format_percentage(value: float, decimals: int = 1) -> str:
    """Format a percentage value."""
    return f"{value:.{decimals}f}%"


def hash_string(s: str) -> str:
    """Create a short hash for anonymization."""
    return hashlib.md5(s.encode()).hexdigest()[:8]


def time_bucket(dt_series: pd.Series, bucket: str = "1H") -> pd.Series:
    """Bucket timestamps into intervals."""
    return dt_series.dt.floor(bucket)


def calculate_percentile(series: pd.Series, percentile: int) -> float:
    """Calculate a given percentile from a numeric series."""
    if series.empty:
        return 0.0
    return float(np.percentile(series.dropna(), percentile))


def get_trend_arrow(current: float, previous: float) -> str:
    """Return trend arrow and color based on comparison."""
    if previous == 0:
        return "→", "#94a3b8"
    change = ((current - previous) / abs(previous)) * 100
    if change > 5:
        return "↑", "#10b981"
    elif change < -5:
        return "↓", "#ef4444"
    else:
        return "→", "#94a3b8"


def get_trend_indicator(current: float, previous: float, lower_is_better: bool = False) -> dict:
    """Get full trend indicator with arrow, color, and percentage change."""
    if previous == 0:
        return {"arrow": "→", "color": "#94a3b8", "change": 0.0, "label": "No change"}
    change = ((current - previous) / abs(previous)) * 100
    if change > 5:
        arrow = "↑"
        color = "#ef4444" if lower_is_better else "#10b981"
        label = f"+{change:.1f}%"
    elif change < -5:
        arrow = "↓"
        color = "#10b981" if lower_is_better else "#ef4444"
        label = f"{change:.1f}%"
    else:
        arrow = "→"
        color = "#94a3b8"
        label = f"{change:.1f}%"
    return {"arrow": arrow, "color": color, "change": change, "label": label}


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Safe division avoiding ZeroDivisionError."""
    if denominator == 0:
        return default
    return numerator / denominator


def classify_status(status_code) -> str:
    """Classify HTTP status codes into categories."""
    try:
        code = int(status_code)
    except (ValueError, TypeError):
        s = str(status_code).lower()
        if s in ("success", "ok", "200", "201", "204"):
            return "success"
        elif s in ("fail", "failed", "error", "denied", "403", "401", "500"):
            return "failure"
        return "other"
    if 200 <= code < 300:
        return "success"
    elif 400 <= code < 500:
        return "client_error"
    elif 500 <= code < 600:
        return "server_error"
    elif 300 <= code < 400:
        return "redirect"
    else:
        return "other"


def is_failure(status_code) -> bool:
    """Check if a status code represents a failure."""
    cat = classify_status(status_code)
    return cat in ("failure", "client_error", "server_error")


def kpi_card_html(title: str, value: str, subtitle: str = "", icon: str = "",
                  trend: dict = None, accent_color: str = "#3b82f6") -> str:
    """Generate HTML for a KPI metric card with hover animation."""
    trend_html = ""
    if trend:
        trend_html = f"""<div style="margin-top:6px; font-size:0.8rem; color:{trend['color']}; font-weight:600;">{trend['arrow']} {trend['label']}</div>"""

    return f"""<div style="background: linear-gradient(145deg, #1a1f2e 0%, #111827 100%); border: 1px solid #1e293b; border-left: 3px solid {accent_color}; border-radius: 12px; padding: 20px 22px; transition: all 0.3s cubic-bezier(0.4,0,0.2,1); cursor: default; position: relative; overflow: hidden;" onmouseover="this.style.transform='translateY(-4px)'; this.style.boxShadow='0 12px 40px rgba(59,130,246,0.15)'; this.style.borderColor='{accent_color}';" onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='none'; this.style.borderColor='#1e293b'; this.style.borderLeftColor='{accent_color}';">
<div style="position:absolute; top:0; right:0; width:80px; height:80px; background: radial-gradient(circle at top right, {accent_color}15, transparent 70%);"></div>
<div style="font-size:1.5rem; margin-bottom:4px;">{icon}</div>
<div style="color:#94a3b8; font-size:0.75rem; text-transform:uppercase; letter-spacing:1.2px; font-weight:600; margin-bottom:8px;">{title}</div>
<div style="color:#f1f5f9; font-size:1.75rem; font-weight:700; line-height:1.2;">{value}</div>
{trend_html}
<div style="color:#64748b; font-size:0.7rem; margin-top:6px;">{subtitle}</div>
</div>"""


def rag_badge_html(status: str, label: str = "") -> str:
    """Generate a RAG status badge."""
    from config.settings import RAG_STATUS
    info = RAG_STATUS.get(status, RAG_STATUS["GREEN"])
    display_label = label or info["label"]
    return f"""<span style="display:inline-flex; align-items:center; gap:6px; background:{info['color']}18; color:{info['color']}; padding:4px 12px; border-radius:20px; font-size:0.75rem; font-weight:600; border:1px solid {info['color']}40;">{info['icon']} {display_label}</span>"""


def severity_badge_html(severity: str) -> str:
    """Generate a severity level badge."""
    from config.settings import SEVERITY
    info = SEVERITY.get(severity, SEVERITY["INFO"])
    return f"""<span style="display:inline-flex; align-items:center; gap:4px; background:{info['color']}18; color:{info['color']}; padding:3px 10px; border-radius:16px; font-size:0.7rem; font-weight:600; border:1px solid {info['color']}40;">{info['icon']} {info['label']}</span>"""


def alert_card_html(title: str, description: str, severity: str,
                    timestamp: str, details: str = "") -> str:
    """Generate an alert card with icon and severity styling."""
    from config.settings import SEVERITY
    info = SEVERITY.get(severity, SEVERITY["INFO"])
    
    details_html = ""
    if details:
        details_html = f"<div style='color:#94a3b8; font-size:0.75rem; margin-top:8px; padding-top:8px; border-top:1px solid #1e293b;'>{details}</div>"

    return f"""<div style="background: linear-gradient(145deg, #1a1f2e, #111827); border: 1px solid {info['color']}40; border-left: 4px solid {info['color']}; border-radius: 10px; padding: 16px 20px; margin-bottom: 10px; transition: all 0.3s ease;" onmouseover="this.style.transform='translateX(4px)'; this.style.boxShadow='0 4px 20px {info['color']}15';" onmouseout="this.style.transform='translateX(0)'; this.style.boxShadow='none';">
<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
<div style="display:flex; align-items:center; gap:8px;">
<span style="font-size:1.2rem;">{info['icon']}</span>
<span style="color:#f1f5f9; font-weight:600; font-size:0.9rem;">{title}</span>
</div>
{severity_badge_html(severity)}
</div>
<div style="color:#94a3b8; font-size:0.8rem; margin-bottom:6px;">{description}</div>
<div style="color:#64748b; font-size:0.7rem;">{timestamp}</div>
{details_html}
</div>"""


def section_header_html(title: str, subtitle: str = "", icon: str = "") -> str:
    """Generate a styled section header."""
    return f"""<div style="margin-bottom:20px; padding-bottom:12px; border-bottom:1px solid #1e293b;">
<div style="display:flex; align-items:center; gap:10px;">
<span style="font-size:1.4rem;">{icon}</span>
<div>
<div style="color:#f1f5f9; font-size:1.3rem; font-weight:700;">{title}</div>
<div style="color:#64748b; font-size:0.8rem; margin-top:2px;">{subtitle}</div>
</div>
</div>
</div>"""
