"""
Log Analyzer X – File Handler
Handles CSV/log file ingestion with schema inference, column auto-mapping,
chunked processing, and caching.
"""

import pandas as pd
import streamlit as st
from difflib import SequenceMatcher
from config.settings import EXPECTED_COLUMNS


def fuzzy_match_column(col_name: str, candidates: list, threshold: float = 0.6) -> str | None:
    """Find the best matching candidate for a column name using fuzzy matching."""
    col_lower = col_name.lower().strip().replace(" ", "_").replace("-", "_")
    # Exact match first
    for candidate in candidates:
        if col_lower == candidate:
            return candidate
    # Fuzzy match
    best_match = None
    best_score = threshold
    for candidate in candidates:
        score = SequenceMatcher(None, col_lower, candidate).ratio()
        if score > best_score:
            best_score = score
            best_match = candidate
    return best_match


def auto_map_columns(df: pd.DataFrame) -> dict:
    """
    Auto-map DataFrame columns to expected schema fields.
    Returns a mapping: {expected_field: actual_column_name}
    """
    mapping = {}
    used_columns = set()

    for field, aliases in EXPECTED_COLUMNS.items():
        df_cols = [c for c in df.columns if c not in used_columns]
        for col in df_cols:
            matched = fuzzy_match_column(col, aliases)
            if matched:
                mapping[field] = col
                used_columns.add(col)
                break

    return mapping


def infer_schema(df: pd.DataFrame) -> dict:
    """Infer the schema of a DataFrame."""
    schema = {}
    for col in df.columns:
        dtype = str(df[col].dtype)
        nunique = df[col].nunique()
        null_pct = (df[col].isnull().sum() / len(df)) * 100
        sample_values = df[col].dropna().head(3).tolist()
        schema[col] = {
            "dtype": dtype,
            "nunique": nunique,
            "null_pct": round(null_pct, 2),
            "sample_values": sample_values,
        }
    return schema


@st.cache_data(show_spinner=False)
def load_csv(file_content: bytes, filename: str, chunk_size: int = 50000) -> pd.DataFrame:
    """
    Load a CSV file with chunked processing support.
    Uses caching to avoid re-reading on Streamlit reruns.
    """
    import io

    try:
        # Try reading the whole file first
        df = pd.read_csv(io.BytesIO(file_content), low_memory=False)

        if len(df) == 0:
            return pd.DataFrame()

        return df

    except Exception as e:
        st.error(f"Failed to parse CSV: {str(e)}")
        return pd.DataFrame()


def validate_upload(df: pd.DataFrame) -> dict:
    """
    Validate uploaded data and return a report.
    """
    report = {
        "total_rows": len(df),
        "total_columns": len(df.columns),
        "columns": list(df.columns),
        "null_counts": df.isnull().sum().to_dict(),
        "duplicate_rows": int(df.duplicated().sum()),
        "issues": [],
        "warnings": [],
    }

    if len(df) == 0:
        report["issues"].append("File contains no data rows.")
        return report

    if len(df.columns) < 3:
        report["warnings"].append("Very few columns detected. Ensure proper CSV format.")

    # Check for minimum expected fields
    mapping = auto_map_columns(df)
    mapped_fields = set(mapping.keys())
    critical_fields = {"timestamp", "ip_address", "status"}
    missing_critical = critical_fields - mapped_fields

    if missing_critical:
        report["warnings"].append(
            f"Could not auto-detect critical columns: {', '.join(missing_critical)}. "
            "The platform will work with reduced functionality."
        )

    report["column_mapping"] = mapping
    report["mapped_fields"] = list(mapped_fields)
    report["unmapped_columns"] = [c for c in df.columns if c not in mapping.values()]

    return report


def render_upload_widget() -> tuple:
    """
    Render the file upload widget and return (DataFrame, validation_report) if file uploaded.
    Returns (None, None) if no file.
    """
    uploaded_file = st.file_uploader(
        "Upload Server Logs (CSV)",
        type=["csv"],
        help="Upload a CSV file with server log data. The platform will auto-detect columns.",
    )

    if uploaded_file is not None:
        file_content = uploaded_file.read()
        file_size_mb = len(file_content) / (1024 * 1024)

        with st.spinner(f"Processing {uploaded_file.name} ({file_size_mb:.1f} MB)..."):
            df = load_csv(file_content, uploaded_file.name)

            if df.empty:
                return None, None

            report = validate_upload(df)
            return df, report

    return None, None
