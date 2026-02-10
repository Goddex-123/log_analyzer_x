"""
Log Analyzer X – Isolation Forest Anomaly Detection
Real ML anomaly detection on session-level features using scikit-learn's Isolation Forest.

Why Isolation Forest?
─────────────────────
Isolation Forest works by randomly selecting a feature and then randomly selecting
a split value between the min and max of the selected feature. Anomalies are isolated
in fewer splits (shorter path lengths), making it efficient for high-dimensional data.

Input Features:
- request_count: Total requests in a session
- error_rate: Fraction of failed requests
- avg_latency: Mean response time
- max_latency: Peak response time
- time_spread_sec: Duration of the session
- unique_endpoints: Number of distinct endpoints accessed

Interpretation:
- Anomaly score ∈ [-1, 1]: scores near -1 are anomalies, near 1 are normal
- Label: -1 = anomaly, 1 = normal
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from config.settings import ML_CONFIG


def prepare_session_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate log data into session-level features for anomaly detection.
    """
    if "session_id" not in df.columns or "timestamp" not in df.columns:
        return pd.DataFrame()

    features = df.groupby("session_id").agg(
        request_count=("session_id", "size"),
        error_rate=("is_failure", "mean") if "is_failure" in df.columns else ("session_id", lambda x: 0),
        avg_latency=("latency_ms", "mean") if "latency_ms" in df.columns else ("session_id", lambda x: 0),
        max_latency=("latency_ms", "max") if "latency_ms" in df.columns else ("session_id", lambda x: 0),
        std_latency=("latency_ms", "std") if "latency_ms" in df.columns else ("session_id", lambda x: 0),
        time_start=("timestamp", "min"),
        time_end=("timestamp", "max"),
        unique_endpoints=("endpoint", "nunique") if "endpoint" in df.columns else ("session_id", lambda x: 1),
        unique_services=("service", "nunique") if "service" in df.columns else ("session_id", lambda x: 1),
        total_bytes=("bytes_sent", "sum") if "bytes_sent" in df.columns else ("session_id", lambda x: 0),
    ).reset_index()

    features["time_spread_sec"] = (features["time_end"] - features["time_start"]).dt.total_seconds()
    features["std_latency"] = features["std_latency"].fillna(0)

    return features


def run_isolation_forest(df: pd.DataFrame) -> dict:
    """
    Run Isolation Forest on session features.
    Returns annotated features with anomaly scores and labels.
    """
    session_features = prepare_session_features(df)

    if session_features.empty or len(session_features) < 10:
        return {
            "results": pd.DataFrame(),
            "anomaly_count": 0,
            "total_sessions": 0,
            "model_info": "Insufficient data for Isolation Forest (need ≥10 sessions).",
        }

    # Select numeric features for model
    feature_cols = ["request_count", "error_rate", "avg_latency", "max_latency",
                    "std_latency", "time_spread_sec", "unique_endpoints", "total_bytes"]
    available_cols = [c for c in feature_cols if c in session_features.columns]

    X = session_features[available_cols].fillna(0).values

    # Standardize
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train Isolation Forest
    config = ML_CONFIG["isolation_forest"]
    model = IsolationForest(
        contamination=config["contamination"],
        n_estimators=config["n_estimators"],
        random_state=config["random_state"],
        n_jobs=-1,
    )

    labels = model.fit_predict(X_scaled)
    scores = model.decision_function(X_scaled)

    # Annotate results
    session_features["anomaly_label"] = labels  # -1 = anomaly, 1 = normal
    session_features["anomaly_score"] = scores
    session_features["is_anomaly"] = labels == -1

    anomaly_count = (labels == -1).sum()

    return {
        "results": session_features,
        "anomaly_count": int(anomaly_count),
        "total_sessions": len(session_features),
        "anomaly_rate": round(anomaly_count / len(session_features) * 100, 2),
        "feature_columns": available_cols,
        "model_info": {
            "algorithm": "Isolation Forest (scikit-learn)",
            "why_chosen": "Effective for high-dimensional anomaly detection without requiring labeled data. "
                          "Works by isolating observations — anomalies are isolated in fewer random splits.",
            "contamination": config["contamination"],
            "n_estimators": config["n_estimators"],
            "features_used": available_cols,
            "interpretation": "Sessions with anomaly_label=-1 exhibit unusual patterns compared to the majority. "
                              "Lower anomaly_score values indicate stronger anomalies. "
                              "Common anomaly traits: unusually high error rates, extreme latencies, or abnormal request volumes.",
        },
    }
