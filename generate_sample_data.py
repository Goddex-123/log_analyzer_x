"""
Log Analyzer X – Sample Log Data Generator
Generates realistic server log data with embedded attack patterns,
latency spikes, and behavioral anomalies for testing.
"""

import csv
import random
import os
from datetime import datetime, timedelta

# ─── Configuration ─────────────────────────────────────────────────
NUM_RECORDS = 50000
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_logs.csv")

USERS = [f"user_{i:04d}" for i in range(1, 201)]
ATTACKER_USERS = ["admin", "root", "test", "guest", "administrator"]

SERVICES = ["auth-service", "api-gateway", "payment-service", "user-service",
            "notification-service", "search-service", "analytics-service",
            "file-service", "billing-service", "inventory-service"]

ENDPOINTS = {
    "auth-service": ["/login", "/logout", "/register", "/reset-password", "/verify-token", "/mfa/verify"],
    "api-gateway": ["/v1/users", "/v1/products", "/v1/orders", "/v1/search", "/v1/health", "/v2/graphql"],
    "payment-service": ["/charge", "/refund", "/subscribe", "/webhook", "/balance"],
    "user-service": ["/profile", "/settings", "/preferences", "/avatar", "/history"],
    "notification-service": ["/send", "/templates", "/status", "/subscribe", "/unsubscribe"],
    "search-service": ["/query", "/suggest", "/index", "/bulk", "/analytics"],
    "analytics-service": ["/events", "/metrics", "/reports", "/dashboards", "/export"],
    "file-service": ["/upload", "/download", "/delete", "/list", "/metadata"],
    "billing-service": ["/invoices", "/payments", "/plans", "/usage", "/credits"],
    "inventory-service": ["/stock", "/orders", "/warehouse", "/forecast", "/alerts"],
}

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
METHOD_WEIGHTS = [50, 30, 10, 5, 5]

COUNTRIES = ["US", "UK", "DE", "IN", "JP", "BR", "AU", "CA", "FR", "SG",
             "RU", "CN", "KR", "NL", "SE"]
NORMAL_COUNTRIES = ["US", "UK", "DE", "IN", "JP", "BR", "AU", "CA", "FR", "SG"]
ANOMALY_COUNTRIES = ["RU", "CN", "KR"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/17.0",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1",
    "python-requests/2.31.0",
    "curl/8.4.0",
    "PostmanRuntime/7.36.0",
    "Go-http-client/2.0",
]

# ─── IP Generation ─────────────────────────────────────────────────
NORMAL_IPS = [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
              for _ in range(500)]
ATTACKER_IPS = [f"185.{random.randint(100,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                for _ in range(15)]
BOT_IPS = [f"45.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
           for _ in range(10)]


def generate_normal_record(ts: datetime) -> dict:
    """Generate a normal server log record."""
    service = random.choice(SERVICES)
    endpoint = random.choice(ENDPOINTS[service])
    method = random.choices(METHODS, weights=METHOD_WEIGHTS, k=1)[0]

    # Normal latency: 20-300ms with occasional spikes
    latency = max(5, random.gauss(120, 60))
    if random.random() < 0.03:  # 3% chance of spike
        latency = random.uniform(500, 2000)

    # Mostly success, some errors
    status_roll = random.random()
    if status_roll < 0.85:
        status = random.choice([200, 200, 200, 201, 204])
    elif status_roll < 0.93:
        status = random.choice([400, 401, 403, 404])
    else:
        status = random.choice([500, 502, 503, 429])

    return {
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": random.choice(USERS),
        "ip_address": random.choice(NORMAL_IPS),
        "status": status,
        "method": method,
        "endpoint": endpoint,
        "service": service,
        "latency_ms": round(latency, 1),
        "country": random.choice(NORMAL_COUNTRIES),
        "user_agent": random.choice(USER_AGENTS[:4]),
        "session_id": f"sess_{random.randint(100000, 999999)}",
        "bytes_sent": random.randint(200, 50000),
    }


def generate_brute_force_records(ts: datetime, count: int = 20) -> list:
    """Generate a burst of brute-force login attempts."""
    attacker_ip = random.choice(ATTACKER_IPS)
    records = []
    for i in range(count):
        record_ts = ts + timedelta(seconds=random.randint(0, 120))
        records.append({
            "timestamp": record_ts.strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": random.choice(ATTACKER_USERS),
            "ip_address": attacker_ip,
            "status": 401 if i < count - 2 else random.choice([401, 200]),
            "method": "POST",
            "endpoint": "/login",
            "service": "auth-service",
            "latency_ms": round(random.uniform(50, 200), 1),
            "country": random.choice(ANOMALY_COUNTRIES),
            "user_agent": random.choice(USER_AGENTS[4:]),
            "session_id": f"sess_{random.randint(100000, 999999)}",
            "bytes_sent": random.randint(100, 500),
        })
    return records


def generate_credential_stuffing_records(ts: datetime, count: int = 15) -> list:
    """Generate credential stuffing pattern: many users from one IP."""
    attacker_ip = random.choice(ATTACKER_IPS)
    records = []
    for i in range(count):
        record_ts = ts + timedelta(seconds=random.randint(0, 60))
        records.append({
            "timestamp": record_ts.strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": f"victim_{random.randint(1, 500):04d}",
            "ip_address": attacker_ip,
            "status": random.choice([401, 401, 401, 403, 200]),
            "method": "POST",
            "endpoint": "/login",
            "service": "auth-service",
            "latency_ms": round(random.uniform(30, 100), 1),
            "country": random.choice(ANOMALY_COUNTRIES),
            "user_agent": "python-requests/2.31.0",
            "session_id": f"sess_{random.randint(100000, 999999)}",
            "bytes_sent": random.randint(100, 300),
        })
    return records


def generate_latency_spike_records(ts: datetime, count: int = 30) -> list:
    """Generate a latency spike event for a service."""
    service = random.choice(["payment-service", "search-service", "api-gateway"])
    records = []
    for _ in range(count):
        record_ts = ts + timedelta(seconds=random.randint(0, 300))
        records.append({
            "timestamp": record_ts.strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": random.choice(USERS),
            "ip_address": random.choice(NORMAL_IPS),
            "status": random.choice([200, 200, 504, 503, 500]),
            "method": random.choice(["GET", "POST"]),
            "endpoint": random.choice(ENDPOINTS[service]),
            "service": service,
            "latency_ms": round(random.uniform(1500, 8000), 1),
            "country": random.choice(NORMAL_COUNTRIES),
            "user_agent": random.choice(USER_AGENTS[:4]),
            "session_id": f"sess_{random.randint(100000, 999999)}",
            "bytes_sent": random.randint(200, 5000),
        })
    return records


def generate_bot_traffic(ts: datetime, count: int = 25) -> list:
    """Generate bot/scraper traffic patterns."""
    bot_ip = random.choice(BOT_IPS)
    records = []
    for _ in range(count):
        record_ts = ts + timedelta(seconds=random.randint(0, 60))
        records.append({
            "timestamp": record_ts.strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": f"bot_{random.randint(1,10)}",
            "ip_address": bot_ip,
            "status": 200,
            "method": "GET",
            "endpoint": random.choice(["/v1/products", "/v1/search", "/v1/users"]),
            "service": "api-gateway",
            "latency_ms": round(random.uniform(10, 50), 1),
            "country": random.choice(ANOMALY_COUNTRIES),
            "user_agent": "Go-http-client/2.0",
            "session_id": f"sess_{random.randint(100000, 999999)}",
            "bytes_sent": random.randint(5000, 100000),
        })
    return records


def generate_logs():
    """Main generation function."""
    print(f"Generating {NUM_RECORDS} log records...")

    records = []
    start_time = datetime(2025, 1, 1, 0, 0, 0)
    end_time = datetime(2025, 1, 8, 0, 0, 0)  # 7 days of data
    total_seconds = int((end_time - start_time).total_seconds())

    # Generate normal traffic
    for _ in range(NUM_RECORDS):
        ts = start_time + timedelta(seconds=random.randint(0, total_seconds))
        records.append(generate_normal_record(ts))

    # Inject attack patterns (~50 brute force events)
    for _ in range(50):
        ts = start_time + timedelta(seconds=random.randint(0, total_seconds))
        records.extend(generate_brute_force_records(ts, random.randint(8, 25)))

    # Inject credential stuffing (~30 events)
    for _ in range(30):
        ts = start_time + timedelta(seconds=random.randint(0, total_seconds))
        records.extend(generate_credential_stuffing_records(ts, random.randint(10, 20)))

    # Inject latency spikes (~20 events)
    for _ in range(20):
        ts = start_time + timedelta(seconds=random.randint(0, total_seconds))
        records.extend(generate_latency_spike_records(ts, random.randint(15, 40)))

    # Inject bot traffic (~15 events)
    for _ in range(15):
        ts = start_time + timedelta(seconds=random.randint(0, total_seconds))
        records.extend(generate_bot_traffic(ts, random.randint(20, 50)))

    # Sort by timestamp
    records.sort(key=lambda x: x["timestamp"])

    # Write CSV
    fieldnames = ["timestamp", "user_id", "ip_address", "status", "method",
                  "endpoint", "service", "latency_ms", "country", "user_agent",
                  "session_id", "bytes_sent"]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    print(f"Generated {len(records)} records -> {OUTPUT_FILE}")
    print(f"  Normal:             ~{NUM_RECORDS}")
    print(f"  Brute force bursts: ~50 events")
    print(f"  Credential stuffing:~30 events")
    print(f"  Latency spikes:     ~20 events")
    print(f"  Bot traffic:        ~15 events")


if __name__ == "__main__":
    generate_logs()
