"""
Log Analyzer X – Chart Builders
All Plotly visualization functions with a consistent dark enterprise theme.
"""

import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from config.settings import COLORS


# ─── Shared Layout Template ────────────────────────────────────────
DARK_TEMPLATE = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#94a3b8", family="Segoe UI, -apple-system, sans-serif", size=12),
    title=dict(font=dict(color="#f1f5f9", size=16)),
    xaxis=dict(gridcolor="#1e293b", zerolinecolor="#1e293b", tickfont=dict(size=10)),
    yaxis=dict(gridcolor="#1e293b", zerolinecolor="#1e293b", tickfont=dict(size=10)),
    legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=10)),
    margin=dict(l=50, r=30, t=50, b=50),
    hoverlabel=dict(bgcolor="#1a1f2e", bordercolor="#3b82f6", font=dict(color="#f1f5f9", size=12)),
)


def apply_dark_theme(fig: go.Figure) -> go.Figure:
    """Apply consistent dark theme to a Plotly figure."""
    fig.update_layout(**DARK_TEMPLATE)
    return fig


# ─── Security Charts ──────────────────────────────────────────────

def attack_timeline_chart(brute_force_df: pd.DataFrame, credential_stuffing_df: pd.DataFrame) -> go.Figure:
    """Create an attack timeline showing brute force and credential stuffing events."""
    fig = go.Figure()

    if not brute_force_df.empty and "timestamp" in brute_force_df.columns:
        fig.add_trace(go.Scatter(
            x=brute_force_df["timestamp"],
            y=brute_force_df.get("attempt_count", [0] * len(brute_force_df)),
            mode="markers+lines",
            name="Brute Force",
            marker=dict(size=10, color=COLORS["accent_red"], symbol="x"),
            line=dict(color=COLORS["accent_red"], width=1, dash="dot"),
            hovertemplate="<b>Brute Force</b><br>Time: %{x}<br>Attempts: %{y}<extra></extra>",
        ))

    if not credential_stuffing_df.empty and "timestamp" in credential_stuffing_df.columns:
        fig.add_trace(go.Scatter(
            x=credential_stuffing_df["timestamp"],
            y=credential_stuffing_df.get("unique_users_targeted", [0] * len(credential_stuffing_df)),
            mode="markers+lines",
            name="Credential Stuffing",
            marker=dict(size=10, color=COLORS["accent_amber"], symbol="diamond"),
            line=dict(color=COLORS["accent_amber"], width=1, dash="dot"),
            hovertemplate="<b>Credential Stuffing</b><br>Time: %{x}<br>Users Targeted: %{y}<extra></extra>",
        ))

    fig.update_layout(
        title="🔐 Attack Timeline",
        xaxis_title="Time",
        yaxis_title="Severity (Attempts / Targets)",
        height=400,
        showlegend=True,
    )
    return apply_dark_theme(fig)


def login_heatmap(df: pd.DataFrame) -> go.Figure:
    """Create a heatmap of login attempts by hour and day of week."""
    if "hour" not in df.columns or "day_of_week" not in df.columns:
        return go.Figure()

    # Filter to auth endpoints if possible
    auth_df = df.copy()
    if "endpoint" in df.columns:
        auth_mask = df["endpoint"].str.contains("login|auth|signin", case=False, na=False)
        if auth_mask.sum() > 0:
            auth_df = df[auth_mask]

    heatmap_data = auth_df.groupby(["day_of_week", "hour"]).size().reset_index(name="count")
    pivot = heatmap_data.pivot_table(index="day_of_week", columns="hour", values="count", fill_value=0)

    day_labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    y_labels = [day_labels[i] if i < len(day_labels) else str(i) for i in pivot.index]

    fig = go.Figure(go.Heatmap(
        z=pivot.values,
        x=[f"{h:02d}:00" for h in pivot.columns],
        y=y_labels,
        colorscale=[[0, "#0a0e17"], [0.25, "#1e3a5f"], [0.5, "#3b82f6"], [0.75, "#8b5cf6"], [1, "#ef4444"]],
        hovertemplate="Day: %{y}<br>Hour: %{x}<br>Attempts: %{z}<extra></extra>",
        colorbar=dict(title="Count", tickfont=dict(color="#94a3b8")),
    ))

    fig.update_layout(
        title="🔥 Login Attempt Heatmap",
        xaxis_title="Hour of Day",
        yaxis_title="Day of Week",
        height=350,
    )
    return apply_dark_theme(fig)


def ip_risk_distribution(ip_reputation_df: pd.DataFrame) -> go.Figure:
    """Create risk score distribution chart for IPs."""
    if ip_reputation_df.empty or "reputation_score" not in ip_reputation_df.columns:
        return go.Figure()

    fig = go.Figure(go.Histogram(
        x=ip_reputation_df["reputation_score"],
        nbinsx=20,
        marker=dict(
            color=ip_reputation_df["reputation_score"],
            colorscale=[[0, COLORS["accent_green"]], [0.5, COLORS["accent_amber"]], [1, COLORS["accent_red"]]],
        ),
        hovertemplate="Score: %{x:.0f}<br>Count: %{y}<extra></extra>",
    ))

    fig.update_layout(
        title="🌐 IP Risk Score Distribution",
        xaxis_title="Risk Score (0-100)",
        yaxis_title="Number of IPs",
        height=350,
    )
    return apply_dark_theme(fig)


# ─── Performance Charts ───────────────────────────────────────────

def latency_distribution(df: pd.DataFrame) -> go.Figure:
    """Create latency distribution histogram per service."""
    if "latency_ms" not in df.columns or "service" not in df.columns:
        return go.Figure()

    services = df["service"].unique()[:6]
    colors = [COLORS["accent_blue"], COLORS["accent_cyan"], COLORS["accent_purple"],
              COLORS["accent_green"], COLORS["accent_amber"], COLORS["accent_pink"]]

    fig = go.Figure()
    for i, service in enumerate(services):
        svc_data = df[df["service"] == service]["latency_ms"]
        fig.add_trace(go.Histogram(
            x=svc_data,
            name=service,
            opacity=0.7,
            marker_color=colors[i % len(colors)],
            nbinsx=30,
        ))

    fig.update_layout(
        title="📊 Latency Distribution by Service",
        xaxis_title="Latency (ms)",
        yaxis_title="Frequency",
        barmode="overlay",
        height=400,
    )
    return apply_dark_theme(fig)


def throughput_chart(throughput_df: pd.DataFrame) -> go.Figure:
    """Create throughput over time chart."""
    if throughput_df.empty or "timestamp" not in throughput_df.columns:
        return go.Figure()

    fig = make_subplots(specs=[[{"secondary_y": True}]])

    fig.add_trace(go.Scatter(
        x=throughput_df["timestamp"],
        y=throughput_df["request_count"],
        name="Throughput",
        fill="tozeroy",
        fillcolor="rgba(59, 130, 246, 0.1)",
        line=dict(color=COLORS["accent_blue"], width=2),
        hovertemplate="Time: %{x}<br>Requests: %{y}<extra></extra>",
    ), secondary_y=False)

    if "error_rate" in throughput_df.columns:
        fig.add_trace(go.Scatter(
            x=throughput_df["timestamp"],
            y=throughput_df["error_rate"],
            name="Error Rate (%)",
            line=dict(color=COLORS["accent_red"], width=2, dash="dash"),
            hovertemplate="Time: %{x}<br>Error Rate: %{y:.1f}%<extra></extra>",
        ), secondary_y=True)

    fig.update_layout(title="⚡ Throughput & Error Rate Over Time", height=400)
    fig.update_yaxes(title_text="Requests", secondary_y=False)
    fig.update_yaxes(title_text="Error Rate (%)", secondary_y=True)
    return apply_dark_theme(fig)


def service_health_gauge(health_df: pd.DataFrame) -> go.Figure:
    """Create service health gauges."""
    if health_df.empty:
        return go.Figure()

    services = health_df.head(6)
    n = len(services)
    cols = min(n, 3)
    rows = (n + cols - 1) // cols

    fig = make_subplots(
        rows=rows, cols=cols,
        specs=[[{"type": "indicator"}] * cols for _ in range(rows)],
        horizontal_spacing=0.05,
        vertical_spacing=0.15,
    )

    for i, (_, row) in enumerate(services.iterrows()):
        r = i // cols + 1
        c = i % cols + 1
        color = COLORS["accent_green"] if row["health_score"] >= 85 else (
            COLORS["accent_amber"] if row["health_score"] >= 60 else COLORS["accent_red"]
        )
        fig.add_trace(go.Indicator(
            mode="gauge+number",
            value=row["health_score"],
            title={"text": row["service"], "font": {"size": 11, "color": "#94a3b8"}},
            number={"font": {"size": 20, "color": color}},
            gauge={
                "axis": {"range": [0, 100], "tickfont": {"size": 8, "color": "#64748b"}},
                "bar": {"color": color},
                "bgcolor": "#1a1f2e",
                "bordercolor": "#1e293b",
                "steps": [
                    {"range": [0, 60], "color": "#1e293b"},
                    {"range": [60, 85], "color": "#1e293b"},
                    {"range": [85, 100], "color": "#1e293b"},
                ],
                "threshold": {"line": {"color": "#f1f5f9", "width": 2}, "thickness": 0.75, "value": row["health_score"]},
            },
        ), row=r, col=c)

    fig.update_layout(title="🏥 Service Health Scores", height=250 * rows)
    return apply_dark_theme(fig)


def latency_percentiles_chart(percentiles_df: pd.DataFrame) -> go.Figure:
    """Create grouped bar chart of latency percentiles per service."""
    if percentiles_df.empty or "service" not in percentiles_df.columns:
        return go.Figure()

    fig = go.Figure()
    for pname, color in [("p50", COLORS["accent_cyan"]), ("p95", COLORS["accent_amber"]), ("p99", COLORS["accent_red"])]:
        if pname in percentiles_df.columns:
            fig.add_trace(go.Bar(
                x=percentiles_df["service"],
                y=percentiles_df[pname],
                name=pname.upper(),
                marker_color=color,
                opacity=0.85,
                hovertemplate=f"{pname.upper()}: %{{y:.0f}}ms<extra></extra>",
            ))

    fig.update_layout(
        title="📈 Latency Percentiles by Service",
        xaxis_title="Service",
        yaxis_title="Latency (ms)",
        barmode="group",
        height=400,
    )
    return apply_dark_theme(fig)


# ─── ML Charts ─────────────────────────────────────────────────────

def anomaly_scatter(if_results: pd.DataFrame) -> go.Figure:
    """Scatter plot of session anomalies from Isolation Forest."""
    if if_results.empty:
        return go.Figure()

    fig = go.Figure()

    normal = if_results[if_results["is_anomaly"] == False]
    anomalies = if_results[if_results["is_anomaly"] == True]

    fig.add_trace(go.Scatter(
        x=normal.get("avg_latency", []),
        y=normal.get("error_rate", []),
        mode="markers",
        name="Normal",
        marker=dict(size=6, color=COLORS["accent_blue"], opacity=0.5),
        hovertemplate="Latency: %{x:.0f}ms<br>Error Rate: %{y:.2%}<extra></extra>",
    ))

    fig.add_trace(go.Scatter(
        x=anomalies.get("avg_latency", []),
        y=anomalies.get("error_rate", []),
        mode="markers",
        name="Anomaly",
        marker=dict(size=10, color=COLORS["accent_red"], symbol="x", line=dict(width=1, color="#fff")),
        hovertemplate="<b>ANOMALY</b><br>Latency: %{x:.0f}ms<br>Error Rate: %{y:.2%}<extra></extra>",
    ))

    fig.update_layout(
        title="🤖 Session Anomaly Detection (Isolation Forest)",
        xaxis_title="Average Latency (ms)",
        yaxis_title="Error Rate",
        height=450,
    )
    return apply_dark_theme(fig)


def cluster_scatter(cluster_results: pd.DataFrame) -> go.Figure:
    """Scatter plot of user clusters from KMeans."""
    if cluster_results.empty or "cluster_label" not in cluster_results.columns:
        return go.Figure()

    fig = px.scatter(
        cluster_results,
        x="total_requests",
        y="failure_rate",
        color="cluster_label",
        size="avg_latency",
        hover_data=["user_id", "unique_services"],
        color_discrete_sequence=[COLORS["accent_blue"], COLORS["accent_green"],
                                 COLORS["accent_amber"], COLORS["accent_red"],
                                 COLORS["accent_purple"], COLORS["accent_cyan"]],
    )

    fig.update_layout(
        title="🧠 User Behavior Clusters (KMeans)",
        xaxis_title="Total Requests",
        yaxis_title="Failure Rate",
        height=450,
    )
    return apply_dark_theme(fig)


def risk_distribution_chart(risk_df: pd.DataFrame) -> go.Figure:
    """Risk score distribution donut chart."""
    if risk_df.empty or "risk_tier" not in risk_df.columns:
        return go.Figure()

    tier_counts = risk_df["risk_tier"].value_counts()
    colors_map = {
        "Low": COLORS["accent_green"],
        "Medium": COLORS["accent_amber"],
        "High": "#f97316",
        "Critical": COLORS["accent_red"],
    }

    fig = go.Figure(go.Pie(
        labels=tier_counts.index.tolist(),
        values=tier_counts.values.tolist(),
        hole=0.55,
        marker=dict(colors=[colors_map.get(t, COLORS["accent_blue"]) for t in tier_counts.index]),
        textinfo="label+percent",
        textfont=dict(color="#f1f5f9", size=12),
        hovertemplate="%{label}: %{value} users (%{percent})<extra></extra>",
    ))

    fig.update_layout(
        title="⚠️ Risk Tier Distribution",
        height=400,
        annotations=[dict(
            text="RISK", x=0.5, y=0.5, font=dict(size=16, color="#94a3b8"),
            showarrow=False, xref="paper", yref="paper",
        )],
    )
    return apply_dark_theme(fig)


# ─── Usage Charts ──────────────────────────────────────────────────

def activity_heatmap(heatmap_data: pd.DataFrame) -> go.Figure:
    """User activity heatmap by hour and day."""
    if heatmap_data.empty:
        return go.Figure()

    pivot = heatmap_data.pivot_table(index="day_of_week", columns="hour", values="count", fill_value=0)
    day_labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    y_labels = [day_labels[i] if i < len(day_labels) else str(i) for i in pivot.index]

    fig = go.Figure(go.Heatmap(
        z=pivot.values,
        x=[f"{h:02d}:00" for h in pivot.columns],
        y=y_labels,
        colorscale=[[0, "#0a0e17"], [0.3, "#1e3a5f"], [0.6, "#3b82f6"], [0.85, "#06b6d4"], [1, "#10b981"]],
        hovertemplate="Day: %{y}<br>Hour: %{x}<br>Requests: %{z}<extra></extra>",
    ))

    fig.update_layout(title="📊 Activity Heatmap", height=300)
    return apply_dark_theme(fig)


def sankey_diagram(df: pd.DataFrame) -> go.Figure:
    """Create Sankey diagram: User Type → Service → Status Category."""
    if "service" not in df.columns or "status_category" not in df.columns:
        return go.Figure()

    # Determine user type based on failure rate
    user_types = df.groupby("user_id")["is_failure"].mean().reset_index()
    user_types["user_type"] = np.where(user_types["is_failure"] > 0.3, "Suspicious", "Normal")
    df_m = df.merge(user_types[["user_id", "user_type"]], on="user_id", how="left")

    # Build flows: user_type → service
    flow1 = df_m.groupby(["user_type", "service"]).size().reset_index(name="count")
    # Build flows: service → status
    flow2 = df_m.groupby(["service", "status_category"]).size().reset_index(name="count")

    # Build node list
    all_nodes = list(flow1["user_type"].unique()) + list(flow1["service"].unique()) + list(flow2["status_category"].unique())
    all_nodes = list(dict.fromkeys(all_nodes))  # dedupe preserving order
    node_idx = {name: i for i, name in enumerate(all_nodes)}

    # Build links
    sources, targets, values = [], [], []
    for _, row in flow1.iterrows():
        sources.append(node_idx[row["user_type"]])
        targets.append(node_idx[row["service"]])
        values.append(row["count"])
    for _, row in flow2.iterrows():
        sources.append(node_idx[row["service"]])
        targets.append(node_idx[row["status_category"]])
        values.append(row["count"])

    # Node colors
    node_colors = []
    for node in all_nodes:
        if node == "Suspicious":
            node_colors.append(COLORS["accent_red"])
        elif node == "Normal":
            node_colors.append(COLORS["accent_green"])
        elif node in ("success",):
            node_colors.append(COLORS["accent_green"])
        elif node in ("client_error", "server_error", "failure"):
            node_colors.append(COLORS["accent_red"])
        else:
            node_colors.append(COLORS["accent_blue"])

    fig = go.Figure(go.Sankey(
        node=dict(
            pad=15, thickness=20,
            label=all_nodes,
            color=node_colors,
        ),
        link=dict(
            source=sources, target=targets, value=values,
            color=["rgba(59,130,246,0.15)"] * len(sources),
        ),
    ))

    fig.update_layout(title="🔀 Request Flow: User Type → Service → Outcome", height=500)
    return apply_dark_theme(fig)


# ─── Trend Charts ─────────────────────────────────────────────────

def trend_line_chart(hourly_df: pd.DataFrame, title: str = "Latency Trend") -> go.Figure:
    """Create trend line chart with moving averages."""
    if hourly_df.empty or "hour_bucket" not in hourly_df.columns:
        return go.Figure()

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=hourly_df["hour_bucket"],
        y=hourly_df["avg_value"],
        mode="lines",
        name="Actual",
        line=dict(color=COLORS["accent_blue"], width=1),
        opacity=0.5,
    ))

    for ma_col, name, color in [
        ("ma_3h", "3h MA", COLORS["accent_cyan"]),
        ("ma_6h", "6h MA", COLORS["accent_purple"]),
        ("ma_12h", "12h MA", COLORS["accent_amber"]),
    ]:
        if ma_col in hourly_df.columns:
            fig.add_trace(go.Scatter(
                x=hourly_df["hour_bucket"],
                y=hourly_df[ma_col],
                mode="lines",
                name=name,
                line=dict(color=color, width=2),
            ))

    fig.update_layout(title=f"📈 {title}", xaxis_title="Time", yaxis_title="Value", height=400)
    return apply_dark_theme(fig)


def anomaly_timeline(spike_df: pd.DataFrame, time_col: str = "hour_bucket") -> go.Figure:
    """Create anomaly spike visualization on timeline."""
    if spike_df.empty or time_col not in spike_df.columns:
        return go.Figure()

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=spike_df[time_col],
        y=spike_df["avg_value"],
        mode="lines+markers",
        name="Metric Value",
        line=dict(color=COLORS["accent_blue"], width=2),
        marker=dict(size=6),
    ))

    # Highlight spikes
    if "is_spike" in spike_df.columns:
        spikes = spike_df[spike_df["is_spike"] == True]
        fig.add_trace(go.Scatter(
            x=spikes[time_col],
            y=spikes["avg_value"],
            mode="markers",
            name="Spike",
            marker=dict(size=14, color=COLORS["accent_red"], symbol="triangle-up",
                        line=dict(width=2, color="#fff")),
        ))

    fig.update_layout(title="🔺 Anomaly Spike Detection", xaxis_title="Time", yaxis_title="Value", height=400)
    return apply_dark_theme(fig)
