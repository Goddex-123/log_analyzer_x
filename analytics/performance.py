"""
Log Analyzer X – Performance Analytics
Latency percentiles, SLA breach detection, error rate tracking,
throughput analysis, and service health scoring.
"""

import pandas as pd
import numpy as np
from config.settings import SLA_THRESHOLDS, RAG_STATUS


def calculate_latency_percentiles(df: pd.DataFrame, group_col: str = "service") -> pd.DataFrame:
    """Calculate p50, p95, p99 latency per group (service/endpoint)."""
    if "latency_ms" not in df.columns or group_col not in df.columns:
        return pd.DataFrame()

    percentiles = df.groupby(group_col)["latency_ms"].agg(
        p50=lambda x: np.percentile(x.dropna(), 50),
        p75=lambda x: np.percentile(x.dropna(), 75),
        p95=lambda x: np.percentile(x.dropna(), 95),
        p99=lambda x: np.percentile(x.dropna(), 99),
        mean="mean",
        std="std",
        count="size",
    ).round(1).reset_index()

    return percentiles


def detect_sla_breaches(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect SLA breaches per service.
    Checks latency thresholds, error rates, and availability.
    """
    if "service" not in df.columns:
        return pd.DataFrame()

    service_metrics = df.groupby("service").agg(
        total_requests=("service", "size"),
        error_count=("is_failure", "sum") if "is_failure" in df.columns else ("service", lambda x: 0),
        p95_latency=("latency_ms", lambda x: np.percentile(x.dropna(), 95)) if "latency_ms" in df.columns else ("service", lambda x: 0),
        p99_latency=("latency_ms", lambda x: np.percentile(x.dropna(), 99)) if "latency_ms" in df.columns else ("service", lambda x: 0),
    ).reset_index()

    service_metrics["error_rate_pct"] = (service_metrics["error_count"] / service_metrics["total_requests"] * 100).round(2)
    service_metrics["availability_pct"] = (100 - service_metrics["error_rate_pct"]).round(2)

    # Check breaches
    breaches = []
    for _, row in service_metrics.iterrows():
        service_breaches = []
        if row["p95_latency"] > SLA_THRESHOLDS["latency_p95_ms"]:
            service_breaches.append(f"p95 latency {row['p95_latency']:.0f}ms > {SLA_THRESHOLDS['latency_p95_ms']}ms")
        if row["p99_latency"] > SLA_THRESHOLDS["latency_p99_ms"]:
            service_breaches.append(f"p99 latency {row['p99_latency']:.0f}ms > {SLA_THRESHOLDS['latency_p99_ms']}ms")
        if row["error_rate_pct"] > SLA_THRESHOLDS["error_rate_pct"]:
            service_breaches.append(f"Error rate {row['error_rate_pct']:.1f}% > {SLA_THRESHOLDS['error_rate_pct']}%")
        if row["availability_pct"] < SLA_THRESHOLDS["availability_pct"]:
            service_breaches.append(f"Availability {row['availability_pct']:.1f}% < {SLA_THRESHOLDS['availability_pct']}%")

        if service_breaches:
            breaches.append({
                "service": row["service"],
                "breach_details": "; ".join(service_breaches),
                "breach_count": len(service_breaches),
                "p95_latency": row["p95_latency"],
                "p99_latency": row["p99_latency"],
                "error_rate_pct": row["error_rate_pct"],
                "availability_pct": row["availability_pct"],
                "severity": "CRITICAL" if len(service_breaches) >= 2 else "WARNING",
            })

    return pd.DataFrame(breaches)


def calculate_throughput(df: pd.DataFrame, interval: str = "1h") -> pd.DataFrame:
    """Calculate request throughput (requests per interval) over time."""
    if "timestamp" not in df.columns:
        return pd.DataFrame()

    throughput = df.set_index("timestamp").resample(interval).agg(
        request_count=("user_id", "size") if "user_id" in df.columns else ("ip_address", "size"),
        error_count=("is_failure", "sum") if "is_failure" in df.columns else ("ip_address", lambda x: 0),
        avg_latency=("latency_ms", "mean") if "latency_ms" in df.columns else ("ip_address", lambda x: 0),
    ).reset_index()

    throughput["error_rate"] = (throughput["error_count"] / throughput["request_count"] * 100).round(2)
    throughput["avg_latency"] = throughput["avg_latency"].round(1)

    return throughput


def calculate_error_rates(df: pd.DataFrame) -> pd.DataFrame:
    """Calculate error rates by service and status code."""
    if "service" not in df.columns or "status" not in df.columns:
        return pd.DataFrame()

    error_breakdown = df.groupby(["service", "status_category"]).size().reset_index(name="count")
    totals = df.groupby("service").size().reset_index(name="total")
    error_breakdown = error_breakdown.merge(totals, on="service")
    error_breakdown["percentage"] = (error_breakdown["count"] / error_breakdown["total"] * 100).round(2)

    return error_breakdown


def calculate_service_health(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate composite service health score (0-100).
    Based on: error rate, latency, throughput stability.
    Returns RAG (Red/Amber/Green) status per service.
    """
    if "service" not in df.columns:
        return pd.DataFrame()

    health = df.groupby("service").agg(
        total_requests=("service", "size"),
        error_count=("is_failure", "sum") if "is_failure" in df.columns else ("service", lambda x: 0),
        avg_latency=("latency_ms", "mean") if "latency_ms" in df.columns else ("service", lambda x: 0),
        p95_latency=("latency_ms", lambda x: np.percentile(x.dropna(), 95)) if "latency_ms" in df.columns else ("service", lambda x: 0),
    ).reset_index()

    health["error_rate"] = health["error_count"] / health["total_requests"]

    # Health score components
    # Error rate: 0% = 100 score, 10% = 0 score
    health["score_errors"] = ((1 - health["error_rate"].clip(0, 0.1) / 0.1) * 100).round(1)

    # Latency: under 200ms = 100, over 2000ms = 0
    health["score_latency"] = ((1 - (health["avg_latency"].clip(0, 2000) - 200) / 1800).clip(0, 1) * 100).round(1)

    # Composite
    health["health_score"] = (health["score_errors"] * 0.6 + health["score_latency"] * 0.4).round(1)

    # RAG status
    def get_rag(score):
        if score >= RAG_STATUS["GREEN"]["threshold"] * 100:
            return "GREEN"
        elif score >= RAG_STATUS["AMBER"]["threshold"] * 100:
            return "AMBER"
        return "RED"

    health["rag_status"] = health["health_score"].apply(get_rag)

    return health.sort_values("health_score")


def identify_bottlenecks(df: pd.DataFrame, n: int = 5) -> list:
    """
    Identify potential bottleneck root causes.
    Returns a list of hints/recommendations.
    """
    hints = []

    if "service" in df.columns and "latency_ms" in df.columns:
        # Slowest services
        slow = df.groupby("service")["latency_ms"].agg(["mean", "std"]).reset_index()
        slow = slow.sort_values("mean", ascending=False).head(3)
        for _, row in slow.iterrows():
            if row["mean"] > 500:
                hints.append({
                    "type": "High Latency",
                    "service": row["service"],
                    "detail": f"Average latency {row['mean']:.0f}ms (σ={row['std']:.0f}ms). Consider caching or query optimization.",
                    "severity": "WARNING" if row["mean"] < 1000 else "CRITICAL",
                })

    if "service" in df.columns and "is_failure" in df.columns:
        # High error services
        err = df.groupby("service")["is_failure"].mean().reset_index()
        err.columns = ["service", "error_rate"]
        err = err.sort_values("error_rate", ascending=False).head(3)
        for _, row in err.iterrows():
            if row["error_rate"] > 0.05:
                hints.append({
                    "type": "High Error Rate",
                    "service": row["service"],
                    "detail": f"Error rate {row['error_rate']*100:.1f}%. Investigate upstream dependencies and failure modes.",
                    "severity": "WARNING" if row["error_rate"] < 0.1 else "CRITICAL",
                })

    return hints[:n]


def run_performance_analysis(df: pd.DataFrame) -> dict:
    """Run the full performance analysis pipeline."""
    latency_percentiles = calculate_latency_percentiles(df)
    sla_breaches = detect_sla_breaches(df)
    throughput = calculate_throughput(df)
    error_rates = calculate_error_rates(df)
    service_health = calculate_service_health(df)
    bottlenecks = identify_bottlenecks(df)

    # Overall system health
    overall_health = service_health["health_score"].mean() if not service_health.empty else 100.0

    return {
        "latency_percentiles": latency_percentiles,
        "sla_breaches": sla_breaches,
        "throughput": throughput,
        "error_rates": error_rates,
        "service_health": service_health,
        "bottlenecks": bottlenecks,
        "overall_health_score": round(overall_health, 1),
        "services_breaching_sla": len(sla_breaches),
    }
