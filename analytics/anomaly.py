"""
Log Analyzer X – Anomaly Detection
Rolling Z-score analysis and spike detection on performance metrics.
"""

import pandas as pd
import numpy as np
from config.settings import ML_CONFIG


def rolling_zscore(series: pd.Series, window: int = None) -> pd.Series:
    """
    Calculate rolling Z-score for a numeric series.
    Points with |Z| > threshold are flagged as anomalies.
    """
    if window is None:
        window = ML_CONFIG["zscore_window"]

    rolling_mean = series.rolling(window=window, min_periods=1).mean()
    rolling_std = series.rolling(window=window, min_periods=1).std().fillna(1)
    rolling_std = rolling_std.replace(0, 1)  # Avoid division by zero

    zscore = (series - rolling_mean) / rolling_std
    return zscore


def detect_spikes(df: pd.DataFrame, metric_col: str = "latency_ms",
                  time_col: str = "hour_bucket", threshold: float = None) -> pd.DataFrame:
    """
    Detect spikes in a metric over time using rolling Z-score.
    Returns a DataFrame of detected spike periods.
    """
    if metric_col not in df.columns or time_col not in df.columns:
        return pd.DataFrame()

    if threshold is None:
        threshold = ML_CONFIG["zscore_threshold"]

    # Aggregate by time bucket
    time_series = df.groupby(time_col)[metric_col].agg(["mean", "std", "count"]).reset_index()
    time_series.columns = [time_col, "avg_value", "std_value", "count"]

    # Calculate rolling Z-score
    time_series["zscore"] = rolling_zscore(time_series["avg_value"])
    time_series["is_spike"] = time_series["zscore"].abs() > threshold
    time_series["spike_direction"] = np.where(
        time_series["zscore"] > threshold, "HIGH",
        np.where(time_series["zscore"] < -threshold, "LOW", "NORMAL")
    )

    spikes = time_series[time_series["is_spike"]].copy()
    spikes["severity"] = np.where(
        spikes["zscore"].abs() > threshold * 1.5, "CRITICAL", "WARNING"
    )

    return spikes


def detect_error_rate_spikes(df: pd.DataFrame, time_col: str = "hour_bucket") -> pd.DataFrame:
    """Detect spikes in error rate over time."""
    if "is_failure" not in df.columns or time_col not in df.columns:
        return pd.DataFrame()

    time_series = df.groupby(time_col).agg(
        total=("is_failure", "size"),
        errors=("is_failure", "sum"),
    ).reset_index()

    time_series["error_rate"] = (time_series["errors"] / time_series["total"] * 100).round(2)
    time_series["zscore"] = rolling_zscore(time_series["error_rate"])
    time_series["is_spike"] = time_series["zscore"] > ML_CONFIG["zscore_threshold"]

    return time_series


def run_anomaly_analysis(df: pd.DataFrame) -> dict:
    """Run the full anomaly detection pipeline."""
    latency_spikes = detect_spikes(df, "latency_ms", "hour_bucket")
    error_spikes = detect_error_rate_spikes(df, "hour_bucket")

    # Per-service anomalies
    service_anomalies = {}
    if "service" in df.columns:
        for service in df["service"].unique():
            svc_df = df[df["service"] == service]
            svc_spikes = detect_spikes(svc_df, "latency_ms", "hour_bucket")
            if not svc_spikes.empty:
                service_anomalies[service] = svc_spikes

    return {
        "latency_spikes": latency_spikes,
        "error_spikes": error_spikes,
        "service_anomalies": service_anomalies,
        "total_latency_spikes": len(latency_spikes),
        "total_error_spikes": len(error_spikes[error_spikes["is_spike"]]) if not error_spikes.empty else 0,
    }
