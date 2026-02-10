# 🛡️ Log Analyzer X
### Enterprise Security & Performance Intelligence Platform

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28%2B-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![Scikit-Learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![Plotly](https://img.shields.io/badge/Plotly-3F4F75?style=for-the-badge&logo=plotly&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

---

**Log Analyzer X** is a production-grade security and performance analytics platform designed for SOC analysts, SREs, and data engineers. It ingests raw server logs and transforms them into actionable intelligence using advanced machine learning, behavioral analytics, and real-time visualization.

## ✨ Key Features

### 🔒 Security Intelligence
- **Threat Detection**: Real-time identification of brute force attacks, credential stuffing, and botnets.
- **MITRE ATT&CK Mapping**: Maps detected anomalies to known adversary tactics and techniques.
- **Geo-Anomalies**: Visualizes suspicious access patterns across global maps.

### 🚀 Performance & SRE
- **SLA Monitoring**: Tracks 95th/99th percentile latency and error rates against defined thresholds.
- **Bottleneck Detection**: Automatically identifies slow endpoints and resource-constrained services.
- **Health Scores**: Composite 0-100 health metrics for every microservice.

### 🧠 Advanced ML Engine
- **Isolation Forest**: Unsupervised anomaly detection for zero-day threat identification.
- **Behavioral Clustering (KMeans)**: Segments users into archetypes (Power Users, Scrapers, Normal) based on activity.
- **Risk Scoring**: Multi-factor risk index for every IP and User ID.

### 📊 Enterprise Reporting
- **Automated Reports**: Generates PDF/HTML reports for Executive Summaries, Security Audits, and SLA Compliance.
- **Visual Analytics**: Interactive heatmaps, Sankey diagrams, and trend timelines.

## 🛠️ Technology Stack

- **Frontend**: Streamlit (with custom CSS injection for Dark Mode)
- **Data Processing**: Pandas, NumPy
- **Machine Learning**: Scikit-Learn (Isolation Forest, KMeans, DBSCAN)
- **Visualization**: Plotly Express, Plotly Graph Objects
- **Reporting**: Jinja2, FPDF2

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Pip

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/log_analyzer_x.git
   cd log_analyzer_x
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   streamlit run app.py
   ```

4. **Generate Data (Optional)**
   - Click the **"🎲 Generate Sample Data"** button in the sidebar to instantly create 50,000+ realistic log records with simulated attacks.
   - Or upload your own CSV log files.

## 📂 Project Structure

```
log_analyzer_x/
├── analytics/       # Security, Usage, Performance engines
├── config/          # Settings, Themes, Thresholds
├── ingestion/       # File handling & Schema inference
├── ml/              # Machine Learning models (IsoForest, KMeans)
├── pages/           # Streamlit dashboard pages
├── reports/         # HTML/PDF report generators
├── utils/           # Shared helpers & formatters
├── visualization/   # Plotly chart definitions
├── app.py           # Main application entry point
└── requirements.txt # Project dependencies
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

<p align="center">
  Built with ❤️ by <b>Antigravity</b>
</p>
