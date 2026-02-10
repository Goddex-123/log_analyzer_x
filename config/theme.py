"""
Log Analyzer X – Custom CSS Theme
Enterprise dark-first design with animations, gradients, and hover effects.
"""

CUSTOM_CSS = """
<style>
    /* ─── Root & Global ──────────────────────────────────────── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

    .stApp {
        background: linear-gradient(180deg, #0a0e17 0%, #0f1420 50%, #0a0e17 100%);
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* ─── Sidebar ────────────────────────────────────────────── */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1117 0%, #111827 100%);
        border-right: 1px solid #1e293b;
    }
    section[data-testid="stSidebar"] .stRadio label {
        color: #94a3b8 !important;
        padding: 8px 16px !important;
        border-radius: 8px !important;
        margin: 2px 0 !important;
        transition: all 0.3s ease !important;
        cursor: pointer !important;
    }
    section[data-testid="stSidebar"] .stRadio label:hover {
        background: rgba(59,130,246,0.1) !important;
        color: #f1f5f9 !important;
    }
    section[data-testid="stSidebar"] .stRadio [data-checked="true"] + label,
    section[data-testid="stSidebar"] .stRadio label[data-checked="true"] {
        background: linear-gradient(135deg, rgba(59,130,246,0.15), rgba(139,92,246,0.1)) !important;
        color: #f1f5f9 !important;
        border-left: 3px solid #3b82f6 !important;
    }

    /* ─── Headers ────────────────────────────────────────────── */
    h1, h2, h3 { color: #f1f5f9 !important; }
    h1 {
        background: linear-gradient(135deg, #3b82f6, #8b5cf6, #06b6d4);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800 !important;
    }

    /* ─── Metrics & Cards ────────────────────────────────────── */
    [data-testid="stMetric"] {
        background: linear-gradient(145deg, #1a1f2e 0%, #111827 100%);
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 16px 20px;
        transition: all 0.3s cubic-bezier(0.4,0,0.2,1);
    }
    [data-testid="stMetric"]:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 30px rgba(59,130,246,0.12);
        border-color: #3b82f6;
    }
    [data-testid="stMetricLabel"] { color: #94a3b8 !important; font-size: 0.8rem !important; }
    [data-testid="stMetricValue"] { color: #f1f5f9 !important; font-weight: 700 !important; }

    /* ─── Tabs ───────────────────────────────────────────────── */
    .stTabs [data-baseweb="tab-list"] {
        background: transparent;
        gap: 4px;
        border-bottom: 1px solid #1e293b;
    }
    .stTabs [data-baseweb="tab"] {
        color: #64748b;
        background: transparent;
        border-radius: 8px 8px 0 0;
        padding: 10px 20px;
        transition: all 0.3s ease;
    }
    .stTabs [data-baseweb="tab"]:hover { color: #f1f5f9; background: rgba(59,130,246,0.08); }
    .stTabs [aria-selected="true"] {
        color: #f1f5f9 !important;
        background: linear-gradient(180deg, rgba(59,130,246,0.15), transparent) !important;
        border-bottom: 2px solid #3b82f6 !important;
    }

    /* ─── DataFrames ─────────────────────────────────────────── */
    .stDataFrame { border-radius: 10px; overflow: hidden; }
    [data-testid="stDataFrame"] th {
        background: #111827 !important;
        color: #94a3b8 !important;
        font-weight: 600 !important;
    }
    [data-testid="stDataFrame"] td { color: #cbd5e1 !important; }

    /* ─── Buttons ────────────────────────────────────────────── */
    .stButton > button {
        background: linear-gradient(135deg, #3b82f6, #2563eb);
        color: white !important;
        border: none;
        border-radius: 8px;
        padding: 8px 24px;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(59,130,246,0.35);
    }
    .stDownloadButton > button {
        background: linear-gradient(135deg, #10b981, #059669);
        border: none; border-radius: 8px; transition: all 0.3s ease;
    }
    .stDownloadButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(16,185,129,0.35);
    }

    /* ─── File Uploader ──────────────────────────────────────── */
    [data-testid="stFileUploader"] {
        border: 2px dashed #1e293b;
        border-radius: 12px;
        background: rgba(17,24,39,0.5);
        transition: all 0.3s ease;
    }
    [data-testid="stFileUploader"]:hover {
        border-color: #3b82f6;
        background: rgba(59,130,246,0.05);
    }

    /* ─── Expanders ──────────────────────────────────────────── */
    .streamlit-expanderHeader {
        background: #1a1f2e !important;
        border-radius: 8px !important;
        color: #f1f5f9 !important;
    }

    /* ─── Animations ─────────────────────────────────────────── */
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
    @keyframes slideIn {
        from { opacity: 0; transform: translateX(-20px); }
        to { opacity: 1; transform: translateX(0); }
    }
    .element-container { animation: fadeInUp 0.4s ease-out; }

    /* ─── Scrollbar ──────────────────────────────────────────── */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #0a0e17; }
    ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #334155; }

    /* ─── Alert boxes ────────────────────────────────────────── */
    .stAlert { border-radius: 10px !important; }

    /* ─── Divider ────────────────────────────────────────────── */
    hr { border-color: #1e293b !important; }

    /* ─── Selectbox / Inputs ─────────────────────────────────── */
    .stSelectbox > div > div { background: #1a1f2e !important; border-color: #1e293b !important; }
    .stTextInput > div > div > input { background: #1a1f2e !important; color: #f1f5f9 !important; }
</style>
"""
