#!/bin/bash

# SDN Security Operations Center Dashboard Launcher
# This script launches the enhanced analytics dashboard

echo "🛡️ Starting SDN Security Operations Center Dashboard..."
echo "📊 Loading enhanced analytics with professional visualizations..."
echo ""
echo "Dashboard will be available at: http://localhost:8501"
echo "Press Ctrl+C to stop the dashboard"
echo ""

# Change to the directory containing the dashboard
cd "$(dirname "$0")"

# Launch the Streamlit dashboard
streamlit run analytics_dashboard.py --server.port 8501 --server.address 0.0.0.0 --server.headless true
