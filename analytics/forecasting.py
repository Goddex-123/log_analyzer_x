"""
Log Analyzer X – Forecasting
Time-series trend detection, moving averages, and simple linear trend extrapolation.
"""

import pandas as pd
import numpy as np


def hourly_trend(df: pd.DataFrame, metric_col: str = "latency_ms") -> pd.DataFrame:
    """
    Aggregate metrics by hour and calculate moving average trend.
    """
    if "hour_bucket" not in df.columns or metric_col not in df.columns:
        return pd.DataFrame()

    hourly = df.groupby("hour_bucket").agg(
        avg_value=(metric_col, "mean"),
        min_value=(metric_col, "min"),
        max_value=(metric_col, "max"),
        count=("hour_bucket", "size"),
    ).reset_index()

    # Moving averages
    hourly["ma_3h"] = hourly["avg_value"].rolling(3, min_periods=1).mean().round(2)
    hourly["ma_6h"] = hourly["avg_value"].rolling(6, min_periods=1).mean().round(2)
    hourly["ma_12h"] = hourly["avg_value"].rolling(12, min_periods=1).mean().round(2)

    return hourly


def daily_trend(df: pd.DataFrame, metric_col: str = "latency_ms") -> pd.DataFrame:
    """Aggregate metrics by day with moving average."""
    if "date" not in df.columns or metric_col not in df.columns:
        return pd.DataFrame()

    daily = df.groupby("date").agg(
        avg_value=(metric_col, "mean"),
        total_requests=("date", "size"),
        error_count=("is_failure", "sum") if "is_failure" in df.columns else ("date", lambda x: 0),
    ).reset_index()

    daily["ma_3d"] = daily["avg_value"].rolling(3, min_periods=1).mean().round(2)
    daily["error_rate"] = (daily["error_count"] / daily["total_requests"] * 100).round(2)

    return daily


def linear_trend(series: pd.Series) -> dict:
    """
    Fit a simple linear trend to a numeric series.
    Returns slope, intercept, and trend direction.
    """
    if len(series) < 3:
        return {"slope": 0, "intercept": 0, "trend": "stable", "r_squared": 0}

    x = np.arange(len(series))
    y = series.values.astype(float)

    # Remove NaNs
    mask = ~np.isnan(y)
    x = x[mask]
    y = y[mask]

    if len(x) < 3:
        return {"slope": 0, "intercept": 0, "trend": "stable", "r_squared": 0}

    coeffs = np.polyfit(x, y, 1)
    slope = coeffs[0]
    intercept = coeffs[1]

    # R-squared
    y_pred = np.polyval(coeffs, x)
    ss_res = np.sum((y - y_pred) ** 2)
    ss_tot = np.sum((y - np.mean(y)) ** 2)
    r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0

    # Trend direction
    if slope > 0.5:
        trend = "increasing"
    elif slope < -0.5:
        trend = "decreasing"
    else:
        trend = "stable"

    return {
        "slope": round(float(slope), 4),
        "intercept": round(float(intercept), 2),
        "trend": trend,
        "r_squared": round(float(r_squared), 4),
    }


def run_forecasting_analysis(df: pd.DataFrame) -> dict:
    """Run the full forecasting pipeline."""
    hourly = hourly_trend(df, "latency_ms")
    daily = daily_trend(df, "latency_ms")

    # Linear trends
    latency_trend = linear_trend(hourly["avg_value"]) if not hourly.empty else {}

    throughput_hourly = hourly_trend(df, "bytes_sent") if "bytes_sent" in df.columns else pd.DataFrame()
    throughput_trend = linear_trend(throughput_hourly["avg_value"]) if not throughput_hourly.empty else {}

    return {
        "hourly_latency": hourly,
        "daily_latency": daily,
        "hourly_throughput": throughput_hourly,
        "latency_trend": latency_trend,
        "throughput_trend": throughput_trend,
    }
