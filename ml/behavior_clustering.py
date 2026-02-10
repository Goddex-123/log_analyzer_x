"""
Log Analyzer X – Behavior Clustering
KMeans and DBSCAN clustering on user behavior vectors.

Why KMeans + DBSCAN?
────────────────────
KMeans: Partitions users into K groups based on behavior similarity (Euclidean distance).
  Good for finding well-separated clusters of "normal" vs "power" vs "suspicious" users.

DBSCAN: Density-based clustering that can find arbitrarily shaped clusters and identify
  noise points (outliers). Useful for detecting bots or anomalous users that don't
  fit any cluster.

Input Features (per user):
- total_requests, failure_rate, avg_latency, unique_services,
  unique_ips, unique_endpoints, total_bytes

Cluster Profiles:
- Power Users: High request count, many services, low error rate
- Normal Users: Moderate activity across all dimensions
- Suspicious: High error rate, unusual access patterns
- Light/Inactive: Very low request counts
"""

import pandas as pd
import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
from config.settings import ML_CONFIG


def prepare_user_features(df: pd.DataFrame) -> pd.DataFrame:
    """Build feature vectors per user for clustering."""
    if "user_id" not in df.columns:
        return pd.DataFrame()

    features = df.groupby("user_id").agg(
        total_requests=("user_id", "size"),
        failure_rate=("is_failure", "mean") if "is_failure" in df.columns else ("user_id", lambda x: 0),
        avg_latency=("latency_ms", "mean") if "latency_ms" in df.columns else ("user_id", lambda x: 0),
        unique_services=("service", "nunique") if "service" in df.columns else ("user_id", lambda x: 1),
        unique_ips=("ip_address", "nunique") if "ip_address" in df.columns else ("user_id", lambda x: 1),
        unique_endpoints=("endpoint", "nunique") if "endpoint" in df.columns else ("user_id", lambda x: 1),
        total_bytes=("bytes_sent", "sum") if "bytes_sent" in df.columns else ("user_id", lambda x: 0),
    ).reset_index()

    return features


def run_kmeans_clustering(df: pd.DataFrame) -> dict:
    """
    Run KMeans clustering on user behavior features.
    """
    user_features = prepare_user_features(df)

    if user_features.empty or len(user_features) < 10:
        return {
            "results": pd.DataFrame(),
            "cluster_profiles": {},
            "model_info": "Insufficient data for clustering (need ≥10 users).",
        }

    feature_cols = ["total_requests", "failure_rate", "avg_latency",
                    "unique_services", "unique_ips", "unique_endpoints", "total_bytes"]
    available_cols = [c for c in feature_cols if c in user_features.columns]

    X = user_features[available_cols].fillna(0).values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # KMeans clustering
    config = ML_CONFIG["kmeans"]
    n_clusters = min(config["n_clusters"], len(user_features) // 2)
    n_clusters = max(2, n_clusters)

    kmeans = KMeans(
        n_clusters=n_clusters,
        random_state=config["random_state"],
        n_init=10,
    )
    labels = kmeans.fit_predict(X_scaled)
    user_features["cluster"] = labels

    # Silhouette score
    sil_score = silhouette_score(X_scaled, labels) if n_clusters > 1 and len(set(labels)) > 1 else 0

    # Cluster profiles
    cluster_profiles = {}
    for cluster_id in range(n_clusters):
        cluster_data = user_features[user_features["cluster"] == cluster_id]
        profile = {
            "size": len(cluster_data),
            "avg_requests": round(cluster_data["total_requests"].mean(), 1),
            "avg_failure_rate": round(cluster_data["failure_rate"].mean() * 100, 2),
            "avg_latency": round(cluster_data["avg_latency"].mean(), 1),
            "avg_services": round(cluster_data["unique_services"].mean(), 1),
        }
        # Label the cluster
        if profile["avg_failure_rate"] > 30:
            profile["label"] = "🚨 Suspicious"
        elif profile["avg_requests"] > user_features["total_requests"].quantile(0.75):
            profile["label"] = "⚡ Power User"
        elif profile["avg_requests"] < user_features["total_requests"].quantile(0.25):
            profile["label"] = "💤 Light User"
        else:
            profile["label"] = "✅ Normal"
        cluster_profiles[cluster_id] = profile

    user_features["cluster_label"] = user_features["cluster"].map(
        {k: v["label"] for k, v in cluster_profiles.items()}
    )

    return {
        "results": user_features,
        "cluster_profiles": cluster_profiles,
        "silhouette_score": round(sil_score, 4),
        "n_clusters": n_clusters,
        "feature_columns": available_cols,
        "model_info": {
            "algorithm": "KMeans (scikit-learn)",
            "why_chosen": "KMeans partitions users into distinct behavioral groups based on activity metrics. "
                          "It's effective for identifying user archetypes (power users, normal, suspicious).",
            "n_clusters": n_clusters,
            "silhouette_score": round(sil_score, 4),
            "features_used": available_cols,
            "interpretation": "Each cluster represents a behavioral archetype. Silhouette score ranges from -1 to 1; "
                              "values > 0.5 indicate well-defined clusters. Suspicious clusters have high failure rates "
                              "and unusual access patterns.",
        },
    }


def run_dbscan_clustering(df: pd.DataFrame) -> dict:
    """
    Run DBSCAN to detect noise/outlier users.
    """
    user_features = prepare_user_features(df)

    if user_features.empty or len(user_features) < 10:
        return {
            "results": pd.DataFrame(),
            "noise_count": 0,
            "model_info": "Insufficient data for DBSCAN.",
        }

    feature_cols = ["total_requests", "failure_rate", "avg_latency",
                    "unique_services", "unique_ips", "unique_endpoints"]
    available_cols = [c for c in feature_cols if c in user_features.columns]

    X = user_features[available_cols].fillna(0).values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    config = ML_CONFIG["dbscan"]
    dbscan = DBSCAN(eps=config["eps"], min_samples=config["min_samples"])
    labels = dbscan.fit_predict(X_scaled)

    user_features["dbscan_cluster"] = labels
    user_features["is_noise"] = labels == -1

    noise_count = (labels == -1).sum()

    return {
        "results": user_features,
        "noise_count": int(noise_count),
        "n_clusters": len(set(labels)) - (1 if -1 in labels else 0),
        "model_info": {
            "algorithm": "DBSCAN (scikit-learn)",
            "why_chosen": "DBSCAN (Density-Based Spatial Clustering of Applications with Noise) identifies "
                          "clusters of arbitrary shape and labels users that don't belong to any cluster as noise. "
                          "Noise users are potential bots or anomalous accounts.",
            "eps": config["eps"],
            "min_samples": config["min_samples"],
            "noise_percentage": round(noise_count / len(user_features) * 100, 2),
            "interpretation": "Users labeled as noise (cluster=-1) don't fit any normal behavior pattern and "
                              "warrant investigation. They may be bots, attackers, or misconfigured clients.",
        },
    }
