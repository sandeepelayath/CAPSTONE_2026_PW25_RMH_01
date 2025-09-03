# --- Streamlit Dynamic Dashboard Version ---
import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np

st.set_page_config(
    page_title="SDN Security Analytics Dashboard", 
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://docs.streamlit.io',
        'Report a bug': None,
        'About': "# SDN ML-Driven Security Dashboard\nReal-time network security monitoring and threat mitigation analytics."
    }
)

# Custom CSS for professional styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: 700;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 0.5rem;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
    }
    .sub-header {
        font-size: 1.2rem;
        color: #666;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-container {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .danger-metric {
        background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
    }
    .warning-metric {
        background: linear-gradient(135deg, #ffa726 0%, #ff7043 100%);
    }
    .success-metric {
        background: linear-gradient(135deg, #66bb6a 0%, #43a047 100%);
    }
    .info-metric {
        background: linear-gradient(135deg, #42a5f5 0%, #1e88e5 100%);
    }
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #f8f9fa 0%, #e9ecef 100%);
    }
    .stAlert {
        border-radius: 10px;
        border-left: 5px solid #1f77b4;
    }
    div[data-testid="metric-container"] {
        background: white;
        border: 1px solid #ddd;
        padding: 1rem;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
</style>
""", unsafe_allow_html=True)

# Auto-refresh: prefer `streamlit-autorefresh` if available, otherwise fall back to a small JS reload.
# Set AUTO_REFRESH_MS to desired interval in milliseconds (e.g. 3000 = 3 seconds).
AUTO_REFRESH_MS = 3000
try:
    from streamlit_autorefresh import st_autorefresh
    # This will cause Streamlit to rerun the script every AUTO_REFRESH_MS milliseconds.
    _autorefresh_count = st_autorefresh(interval=AUTO_REFRESH_MS, limit=None, key="auto_refresh")
    st.sidebar.info(f"Auto-refresh enabled: {AUTO_REFRESH_MS//1000}s")
except Exception:
    # Fallback: inject small JS to reload the page periodically.
    from streamlit.components.v1 import html as _st_html
    _st_html(f"<script>setInterval(()=>{{window.location.reload();}}, {AUTO_REFRESH_MS});</script>", height=0)
    st.sidebar.info(f"Auto-refresh (JS fallback) enabled: {AUTO_REFRESH_MS//1000}s")

CONTROLLER_DIR = "/home/sandeep/Capstone_Phase3/controller"
ANOMALY_LOG = os.path.join(CONTROLLER_DIR, "anomaly_log.json")
MITIGATION_LOG = os.path.join(CONTROLLER_DIR, "risk_mitigation_actions.json")
LEGACY_LOG = os.path.join(CONTROLLER_DIR, "mitigation_actions.json")

def load_json_lines(filepath):
    data = []
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            for line in f:
                try:
                    data.append(json.loads(line.strip()))
                except:
                    pass
    return data

def load_ip_lists():
    """Extract IP lists from controller and mitigation manager files"""
    controller_file = os.path.join(CONTROLLER_DIR, "ryu_controller.py")
    mitigation_file = os.path.join(CONTROLLER_DIR, "mitigation_manager.py")
    
    whitelist = set()
    blacklist = set()
    honeypot_ips = set()
    
    # Extract from controller file
    if os.path.exists(controller_file):
        try:
            with open(controller_file, 'r') as f:
                content = f.read()
                # Look for whitelist definition
                if 'self.whitelist = set([' in content:
                    import re
                    whitelist_match = re.search(r'self\.whitelist = set\(\[(.*?)\]\)', content, re.DOTALL)
                    if whitelist_match:
                        whitelist_str = whitelist_match.group(1)
                        # Extract IP addresses from the string
                        ip_matches = re.findall(r"'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'", whitelist_str)
                        whitelist = set(ip_matches)
                
                # Look for blacklist (usually dynamic, but check for hardcoded ones)
                if 'self.blacklist = set(' in content:
                    blacklist_match = re.search(r'self\.blacklist = set\(\[(.*?)\]\)', content, re.DOTALL)
                    if blacklist_match:
                        blacklist_str = blacklist_match.group(1)
                        ip_matches = re.findall(r"'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'", blacklist_str)
                        blacklist = set(ip_matches)
        except Exception as e:
            st.error(f"Error reading controller file: {e}")
    
    # Extract honeypot IPs from mitigation manager
    if os.path.exists(mitigation_file):
        try:
            with open(mitigation_file, 'r') as f:
                content = f.read()
                # Look for honeypot_ips definition
                if 'self.honeypot_ips = {' in content:
                    import re
                    honeypot_match = re.search(r'self\.honeypot_ips = \{(.*?)\}', content, re.DOTALL)
                    if honeypot_match:
                        honeypot_str = honeypot_match.group(1)
                        # Extract IP addresses
                        ip_matches = re.findall(r"'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'", honeypot_str)
                        honeypot_ips = set(ip_matches)
        except Exception as e:
            st.error(f"Error reading mitigation manager file: {e}")
    
    # Also check for dynamic blacklist from recent mitigation actions
    mitigation_data = load_json_lines(MITIGATION_LOG)
    if mitigation_data:
        dynamic_blacklist = set()
        for action in mitigation_data:
            if action.get('action_type') in ['BLOCK', 'SHORT_TIMEOUT_BLOCK']:
                if action.get('source_ip'):
                    dynamic_blacklist.add(action['source_ip'])
        blacklist.update(dynamic_blacklist)
    
    # Ensure mutual exclusivity: Remove any IPs that appear in both lists
    # Prioritize whitelist over blacklist for safety
    conflicts = whitelist.intersection(blacklist)
    if conflicts:
        st.warning(f"⚠️ Found {len(conflicts)} IPs in both whitelist and blacklist: {conflicts}")
        st.info("🔧 Prioritizing whitelist over blacklist for safety")
        blacklist = blacklist - conflicts
    
    return whitelist, blacklist, honeypot_ips

def load_data():
    anomaly_data = load_json_lines(ANOMALY_LOG)
    mitigation_data = load_json_lines(MITIGATION_LOG) + load_json_lines(LEGACY_LOG)
    
    # Debug: Print data structure for troubleshooting
    if anomaly_data:
        print(f"📊 Loaded {len(anomaly_data)} anomaly records")
        print(f"Sample anomaly record: {anomaly_data[0]}")
    else:
        print("⚠️ No anomaly data found")
    
    if mitigation_data:
        print(f"🛡️ Loaded {len(mitigation_data)} mitigation records")
        print(f"Sample mitigation record: {mitigation_data[0]}")
    else:
        print("⚠️ No mitigation data found")
    
    return anomaly_data, mitigation_data

def create_risk_distribution_chart(mitigation_df):
    """Create a risk distribution donut chart"""
    if mitigation_df.empty or 'action_type' not in mitigation_df.columns:
        return None
    
    action_counts = mitigation_df['action_type'].value_counts()
    
    # Map actions to risk levels and colors
    risk_mapping = {
        'ALLOW': ('Low Risk', '#28a745'),
        'RATE_LIMIT': ('Medium Risk', '#ffc107'), 
        'SHORT_TIMEOUT_BLOCK': ('High Risk', '#fd7e14'),
        'BLOCK': ('Critical Risk', '#dc3545')
    }
    
    labels = []
    values = []
    colors = []
    
    for action, count in action_counts.items():
        risk_level, color = risk_mapping.get(action, (action, '#6c757d'))
        labels.append(f"{risk_level}<br>({action})")
        values.append(count)
        colors.append(color)
    
    try:
        fig = go.Figure(data=[go.Pie(
            labels=labels, 
            values=values,
            hole=0.4,
            marker_colors=colors,
            textinfo='label+percent+value',
            textfont_size=12,
            hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
        )])
        
        fig.update_layout(
            title={
                'text': "Risk Distribution by Action Type",
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 18, 'color': '#1f77b4'}
            },
            height=400,
            showlegend=True,
            legend=dict(orientation="v", yanchor="middle", y=0.5, xanchor="left", x=1.01),
            margin=dict(l=20, r=20, t=60, b=20)
        )
        return fig
    except ImportError:
        return None

def create_risk_timeline_chart(mitigation_df):
    """Create a timeline chart of risk events"""
    if mitigation_df.empty or 'timestamp' not in mitigation_df.columns:
        return None
    
    try:
        # Convert timestamp and create hourly bins
        mitigation_df['datetime'] = pd.to_datetime(mitigation_df['timestamp'])
        mitigation_df['hour'] = mitigation_df['datetime'].dt.floor('H')
        
        # Group by hour and action type
        hourly_data = mitigation_df.groupby(['hour', 'action_type']).size().unstack(fill_value=0)
        
        fig = go.Figure()
        
        colors = {'ALLOW': '#28a745', 'RATE_LIMIT': '#ffc107', 'SHORT_TIMEOUT_BLOCK': '#fd7e14', 'BLOCK': '#dc3545'}
        
        for action_type in hourly_data.columns:
            fig.add_trace(go.Scatter(
                x=hourly_data.index,
                y=hourly_data[action_type],
                mode='lines+markers',
                name=action_type,
                line=dict(color=colors.get(action_type, '#6c757d'), width=3),
                marker=dict(size=6),
                hovertemplate=f'<b>{action_type}</b><br>Time: %{{x}}<br>Count: %{{y}}<extra></extra>'
            ))
        
        fig.update_layout(
            title={
                'text': "Security Events Timeline (Hourly)",
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 18, 'color': '#1f77b4'}
            },
            xaxis_title="Time",
            yaxis_title="Event Count",
            height=400,
            hovermode='x unified',
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            margin=dict(l=50, r=20, t=80, b=50)
        )
        return fig
    except (ImportError, Exception):
        return None

def create_risk_score_histogram(mitigation_df):
    """Create a histogram of risk scores"""
    if mitigation_df.empty or 'risk_score' not in mitigation_df.columns:
        return None
    
    try:
        risk_scores = pd.to_numeric(mitigation_df['risk_score'], errors='coerce').dropna()
        
        fig = go.Figure(data=[go.Histogram(
            x=risk_scores,
            nbinsx=20,
            marker_color='rgba(31, 119, 180, 0.7)',
            marker_line=dict(color='rgba(31, 119, 180, 1)', width=1),
            hovertemplate='Risk Score Range: %{x}<br>Count: %{y}<extra></extra>'
        )])
        
        # Add vertical lines for risk thresholds
        fig.add_vline(x=0.3, line_dash="dash", line_color="orange", 
                     annotation_text="Medium Risk Threshold", annotation_position="top")
        fig.add_vline(x=0.7, line_dash="dash", line_color="red",
                     annotation_text="High Risk Threshold", annotation_position="top")
        
        fig.update_layout(
            title={
                'text': "Risk Score Distribution",
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 18, 'color': '#1f77b4'}
            },
            xaxis_title="Risk Score",
            yaxis_title="Frequency",
            height=400,
            margin=dict(l=50, r=20, t=60, b=50)
        )
        return fig
    except (ImportError, Exception):
        return None

def create_top_sources_chart(mitigation_df):
    """Create a bar chart of top threat sources"""
    if mitigation_df.empty or 'source_ip' not in mitigation_df.columns:
        return None
    
    try:
        # Get top 10 sources by event count
        top_sources = mitigation_df['source_ip'].value_counts().head(10)
        
        # Calculate average risk score for each source
        avg_risk = mitigation_df.groupby('source_ip')['risk_score'].apply(
            lambda x: pd.to_numeric(x, errors='coerce').mean()
        )
        
        fig = go.Figure()
        
        # Color bars based on average risk score
        colors = ['#dc3545' if avg_risk.get(ip, 0) > 0.7 else 
                 '#fd7e14' if avg_risk.get(ip, 0) > 0.3 else '#28a745' 
                 for ip in top_sources.index]
        
        fig.add_trace(go.Bar(
            x=top_sources.index,
            y=top_sources.values,
            marker_color=colors,
            text=top_sources.values,
            textposition='auto',
            hovertemplate='<b>%{x}</b><br>Events: %{y}<br>Avg Risk: %{customdata:.3f}<extra></extra>',
            customdata=[avg_risk.get(ip, 0) for ip in top_sources.index]
        ))
        
        fig.update_layout(
            title={
                'text': "Top 10 Source IPs by Event Count",
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 18, 'color': '#1f77b4'}
            },
            xaxis_title="Source IP",
            yaxis_title="Event Count",
            height=400,
            margin=dict(l=50, r=20, t=60, b=50)
        )
        return fig
    except (ImportError, Exception):
        return None

def main():
    # Professional header
    st.markdown('<h1 class="main-header">🛡️ SDN Security Operations Center</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Real-time ML-driven network security monitoring and threat mitigation analytics</p>', unsafe_allow_html=True)
    
    # Status indicators
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.info(f"🕒 **System Time:** {current_time} | 🔄 **Auto-refresh:** {AUTO_REFRESH_MS//1000}s | 📊 **Status:** Active")

    refresh = st.button("🔄 Refresh Data", help="Click to manually refresh all data")
    anomaly_data, mitigation_data = load_data()
    anomaly_df = pd.DataFrame(anomaly_data)
    mitigation_df = pd.DataFrame(mitigation_data)

    # Enhanced sidebar with professional styling
    st.sidebar.markdown("## 📋 Navigation Panel")
    tab = st.sidebar.radio("Select View", [
        "🏠 Executive Dashboard",
        "🛡️ Active Mitigations", 
        "⚙️ System Configuration",
        "🎯 Threat Intelligence",
        "📈 Analytics & Reports",
        "🔍 Source Investigation"
    ], help="Navigate between different dashboard sections")

    if tab == "🏠 Executive Dashboard":
        st.markdown("## 📊 Executive Security Dashboard")
        st.markdown("---")
        
        # Key Performance Indicators (KPIs)
        if not mitigation_df.empty:
            # Calculate metrics
            total_events = len(mitigation_df)
            allow_actions = mitigation_df[mitigation_df['action_type'] == 'ALLOW'] if 'action_type' in mitigation_df.columns else pd.DataFrame()
            rate_limit_actions = mitigation_df[mitigation_df['action_type'] == 'RATE_LIMIT'] if 'action_type' in mitigation_df.columns else pd.DataFrame()
            block_actions = mitigation_df[mitigation_df['action_type'].isin(['SHORT_TIMEOUT_BLOCK', 'BLOCK'])] if 'action_type' in mitigation_df.columns else pd.DataFrame()
            
            # Risk calculations
            if 'risk_score' in mitigation_df.columns:
                risk_scores = pd.to_numeric(mitigation_df['risk_score'], errors='coerce').dropna()
                avg_risk = risk_scores.mean() if len(risk_scores) > 0 else 0
                max_risk = risk_scores.max() if len(risk_scores) > 0 else 0
                high_risk_events = (risk_scores >= 0.7).sum() if len(risk_scores) > 0 else 0
                # Calculate low risk flows (using thresholds from mitigation manager: < 0.08)
                low_risk_events = (risk_scores < 0.08).sum() if len(risk_scores) > 0 else 0
            else:
                avg_risk = max_risk = high_risk_events = low_risk_events = 0
            
            # Recent activity (last 24 hours)
            if 'timestamp' in mitigation_df.columns:
                mitigation_df['datetime'] = pd.to_datetime(mitigation_df['timestamp'], errors='coerce')
                recent_cutoff = datetime.now() - timedelta(hours=24)
                recent_events = mitigation_df[mitigation_df['datetime'] > recent_cutoff] if 'datetime' in mitigation_df.columns else pd.DataFrame()
                recent_count = len(recent_events)
                recent_blocks = len(recent_events[recent_events['action_type'].isin(['SHORT_TIMEOUT_BLOCK', 'BLOCK'])]) if not recent_events.empty else 0
                # Calculate recent low risk allowed flows
                recent_allowed = len(recent_events[recent_events['action_type'] == 'ALLOW']) if not recent_events.empty else 0
            else:
                recent_count = recent_blocks = recent_allowed = 0
            
            # Top-level KPI metrics (expanded to 6 columns)
            st.markdown("### 🎯 Key Performance Indicators")
            kpi_col1, kpi_col2, kpi_col3, kpi_col4, kpi_col5, kpi_col6 = st.columns(6)
            
            with kpi_col1:
                st.metric(
                    label="🔍 Total Events",
                    value=f"{total_events:,}",
                    delta=f"+{recent_count} (24h)",
                    help="Total security events processed by the system"
                )
            
            with kpi_col2:
                threat_percentage = (len(block_actions) / total_events * 100) if total_events > 0 else 0
                st.metric(
                    label="🚨 Threats Blocked",
                    value=f"{len(block_actions):,}",
                    delta=f"{threat_percentage:.1f}% of total",
                    delta_color="inverse",
                    help="Number of high-risk threats blocked"
                )
            
            with kpi_col3:
                st.metric(
                    label="⚠️ Rate Limited",
                    value=f"{len(rate_limit_actions):,}",
                    delta=f"+{len(recent_events[recent_events['action_type'] == 'RATE_LIMIT']) if not recent_events.empty else 0} (24h)",
                    help="Medium-risk sources with applied rate limiting"
                )
            
            with kpi_col4:
                st.metric(
                    label="📊 Avg Risk Score",
                    value=f"{avg_risk:.3f}",
                    delta=f"Max: {max_risk:.3f}",
                    help="Average risk score across all events"
                )
            
            with kpi_col5:
                unique_sources = mitigation_df['source_ip'].nunique() if 'source_ip' in mitigation_df.columns else 0
                st.metric(
                    label="🌐 Unique Sources",
                    value=f"{unique_sources:,}",
                    delta=f"{high_risk_events} high-risk",
                    delta_color="inverse",
                    help="Total unique IP addresses monitored"
                )
            
            with kpi_col6:
                allowed_percentage = (len(allow_actions) / total_events * 100) if total_events > 0 else 0
                st.metric(
                    label="✅ Low Risk Allowed",
                    value=f"{len(allow_actions):,}",
                    delta=f"{allowed_percentage:.1f}% of total",
                    delta_color="normal",
                    help="Low-risk flows that were allowed through the system"
                )
            
            st.markdown("---")
            
            # Charts section
            st.markdown("### 📈 Analytics & Visualizations")
            
            chart_col1, chart_col2 = st.columns(2)
            
            with chart_col1:
                # Risk distribution chart
                risk_chart = create_risk_distribution_chart(mitigation_df)
                if risk_chart:
                    st.plotly_chart(risk_chart, use_container_width=True)
                else:
                    # Fallback chart using Streamlit's built-in charting
                    if 'action_type' in mitigation_df.columns:
                        action_counts = mitigation_df['action_type'].value_counts()
                        st.bar_chart(action_counts)
                    else:
                        st.info("Risk distribution data not available")
            
            with chart_col2:
                # Risk score histogram
                risk_hist_chart = create_risk_score_histogram(mitigation_df)
                if risk_hist_chart:
                    st.plotly_chart(risk_hist_chart, use_container_width=True)
                else:
                    # Fallback histogram
                    if 'risk_score' in mitigation_df.columns:
                        risk_scores = pd.to_numeric(mitigation_df['risk_score'], errors='coerce').dropna()
                        if len(risk_scores) > 0:
                            st.bar_chart(pd.cut(risk_scores, bins=10).value_counts().sort_index())
                    else:
                        st.info("Risk score data not available")
            
            # Timeline chart (full width)
            st.markdown("#### 🕒 Security Events Timeline")
            timeline_chart = create_risk_timeline_chart(mitigation_df)
            if timeline_chart:
                st.plotly_chart(timeline_chart, use_container_width=True)
            else:
                st.info("Timeline data not available - enable plotly for interactive charts")
            
            # Top sources chart
            st.markdown("#### 🎯 Top Threat Sources")
            sources_chart = create_top_sources_chart(mitigation_df)
            if sources_chart:
                st.plotly_chart(sources_chart, use_container_width=True)
            else:
                # Fallback top sources table
                if 'source_ip' in mitigation_df.columns:
                    top_sources = mitigation_df['source_ip'].value_counts().head(10)
                    st.dataframe(top_sources.to_frame('Event Count'), use_container_width=True)
                else:
                    st.info("Source IP data not available")
            
        else:
            # No data available
            st.warning("⚠️ No mitigation data available")
            st.info("""
            **Getting Started:**
            1. Ensure the SDN controller is running
            2. Generate some network traffic for analysis
            3. Check that log files are being created in the controller directory
            4. Refresh this dashboard to see updated data
            """)
            
            # Show expected file paths
            st.markdown("#### 📁 Expected Data Sources:")
            st.code(f"""
            Anomaly Log: {ANOMALY_LOG}
            Mitigation Log: {MITIGATION_LOG}
            Legacy Log: {LEGACY_LOG}
            """)
            
            # Show file status
            for filepath, label in [(ANOMALY_LOG, "Anomaly Log"), (MITIGATION_LOG, "Mitigation Log"), (LEGACY_LOG, "Legacy Log")]:
                if os.path.exists(filepath):
                    file_size = os.path.getsize(filepath)
                    st.success(f"✅ **{label}**: Found ({file_size} bytes)")
                else:
                    st.error(f"❌ **{label}**: Not found")

    elif tab == "🛡️ Active Mitigations":
        st.header("🛡️ Active Security Mitigations")
        st.markdown("---")
        if not mitigation_df.empty:
            latest_actions = mitigation_df.drop_duplicates('source_ip', keep='last')
            active = latest_actions[latest_actions['action_type'].isin(['RATE_LIMIT', 'SHORT_TIMEOUT_BLOCK', 'BLOCK'])]
            if not active.empty:
                st.markdown(f"### 🚨 {len(active)} Active Mitigations")
                
                # Add filtering options
                filter_col1, filter_col2 = st.columns(2)
                with filter_col1:
                    action_filter = st.multiselect(
                        "Filter by Action Type",
                        options=active['action_type'].unique(),
                        default=active['action_type'].unique(),
                        help="Select action types to display"
                    )
                with filter_col2:
                    if 'risk_score' in active.columns:
                        risk_threshold = st.slider(
                            "Minimum Risk Score",
                            min_value=0.0,
                            max_value=1.0,
                            value=0.0,
                            step=0.1,
                            help="Show only sources above this risk threshold"
                        )
                        filtered_active = active[
                            (active['action_type'].isin(action_filter)) & 
                            (pd.to_numeric(active['risk_score'], errors='coerce') >= risk_threshold)
                        ]
                    else:
                        filtered_active = active[active['action_type'].isin(action_filter)]
                
                if not filtered_active.empty:
                    # Enhanced display with color coding
                    display_df = filtered_active[['source_ip', 'action_type', 'risk_score', 'risk_level', 'details']].tail(15)
                    st.dataframe(
                        display_df,
                        use_container_width=True,
                        column_config={
                            "source_ip": st.column_config.TextColumn("Source IP", help="IP address under mitigation"),
                            "action_type": st.column_config.TextColumn("Action", help="Type of mitigation applied"),
                            "risk_score": st.column_config.NumberColumn("Risk Score", format="%.3f", help="Calculated risk score"),
                            "risk_level": st.column_config.TextColumn("Risk Level", help="Risk category"),
                            "details": st.column_config.TextColumn("Details", help="Additional information")
                        }
                    )
                else:
                    st.info("No mitigations match the current filters")
            else:
                st.success("✅ No active mitigations - all sources are currently allowed")
        else:
            st.info("No mitigation data available")

    elif tab == "⚙️ System Configuration":
        st.header("🔧 IP Lists & Configuration")
        
        whitelist, blacklist, honeypot_ips = load_ip_lists()
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.subheader("✅ Whitelist")
            st.caption("Trusted IPs that bypass all security checks")
            if whitelist:
                for ip in sorted(whitelist):
                    st.write(f"• {ip}")
            else:
                st.info("No whitelisted IPs configured")
        
        with col2:
            st.subheader("🚫 Blacklist")
            st.caption("Blocked IPs (static + dynamic)")
            if blacklist:
                for ip in sorted(blacklist):
                    st.write(f"• {ip}")
            else:
                st.info("No blacklisted IPs found")
        
        with col3:
            st.subheader("🍯 Honeypot IPs")
            st.caption("Trap IPs that trigger immediate blocking")
            if honeypot_ips:
                for ip in sorted(honeypot_ips):
                    st.write(f"• {ip}")
            else:
                st.info("No honeypot IPs configured")
        
        st.divider()
        
        # Configuration summary
        st.subheader("📊 Configuration Summary")
        config_col1, config_col2, config_col3, config_col4 = st.columns(4)
        
        with config_col1:
            st.metric("Whitelisted IPs", len(whitelist))
        with config_col2:
            st.metric("Blacklisted IPs", len(blacklist))
        with config_col3:
            st.metric("Honeypot IPs", len(honeypot_ips))
        with config_col4:
            total_monitored = len(whitelist) + len(blacklist) + len(honeypot_ips)
            st.metric("Total Monitored", total_monitored)
        
        # Show recent blacklist additions
        if not mitigation_df.empty:
            st.subheader("🕒 Recent Blacklist Additions")
            recent_blocks = mitigation_df[mitigation_df['action_type'].isin(['BLOCK', 'SHORT_TIMEOUT_BLOCK'])].tail(10)
            if not recent_blocks.empty:
                st.dataframe(recent_blocks[['timestamp', 'source_ip', 'action_type', 'risk_score', 'details']], use_container_width=True)
            else:
                st.info("No recent blocking actions found")
        
        # Show conflict resolution information
        st.divider()
        st.subheader("🔧 List Management")
        st.info("""
        **List Priority Order:**
        1. **Whitelist** (Highest Priority) - Bypasses all security checks
        2. **Blacklist** (High Priority) - Blocks traffic immediately  
        3. **Honeypot** (Special) - Triggers immediate blocking of sources
        
        **Automatic Conflict Resolution:**
        - Adding to whitelist automatically removes from blacklist
        - Adding to blacklist automatically removes from whitelist
        - This ensures mutual exclusivity and consistent behavior
        """)
        
        if total_monitored > 0:
            st.success(f"✅ System is monitoring {total_monitored} IPs across all lists")
        
        # Admin Controls Section
        st.divider()
        st.subheader("🔧 Admin Controls")
        
        admin_col1, admin_col2 = st.columns(2)
        
        with admin_col1:
            st.write("### ➕ Add IP to Lists")
            
            # Input for new IP
            new_ip = st.text_input("Enter IP Address", placeholder="10.0.0.x")
            
            # Validate IP format
            is_valid_ip = False
            if new_ip:
                try:
                    import ipaddress
                    ipaddress.IPv4Address(new_ip)
                    is_valid_ip = True
                except:
                    st.error("⚠️ Invalid IP address format")
            
            if is_valid_ip:
                add_col1, add_col2, add_col3 = st.columns(3)
                
                with add_col1:
                    if st.button("➕ Add to Whitelist", key="add_whitelist"):
                        if new_ip in blacklist:
                            st.warning(f"⚠️ {new_ip} is currently blacklisted and will be removed from blacklist")
                        st.success(f"✅ Would add {new_ip} to whitelist")
                        st.info("💡 Restart controller to apply changes")
                
                with add_col2:
                    if st.button("➕ Add to Blacklist", key="add_blacklist"):
                        if new_ip in whitelist:
                            st.warning(f"⚠️ {new_ip} is currently whitelisted and will be removed from whitelist")
                        st.success(f"✅ Would add {new_ip} to blacklist")
                        st.info("💡 Restart controller to apply changes")
                
                with add_col3:
                    if st.button("➕ Add to Honeypot", key="add_honeypot"):
                        st.success(f"✅ Would add {new_ip} to honeypot list")
                        st.info("💡 Edit mitigation_manager.py manually and restart")
        
        with admin_col2:
            st.write("### ➖ Remove IP from Lists")
            
            # Show current IPs for removal
            all_monitored_ips = sorted(list(whitelist) + list(blacklist) + list(honeypot_ips))
            
            if all_monitored_ips:
                selected_ip = st.selectbox("Select IP to Remove", ["Select IP..."] + all_monitored_ips)
                
                if selected_ip != "Select IP...":
                    # Show current status
                    status_parts = []
                    if selected_ip in whitelist:
                        status_parts.append("✅ Whitelist")
                    if selected_ip in blacklist:
                        status_parts.append("🚫 Blacklist")
                    if selected_ip in honeypot_ips:
                        status_parts.append("🍯 Honeypot")
                    
                    st.info(f"Current status: {', '.join(status_parts)}")
                    
                    remove_col1, remove_col2, remove_col3 = st.columns(3)
                    
                    with remove_col1:
                        if selected_ip in whitelist and st.button("➖ Remove from Whitelist", key="remove_whitelist"):
                            st.success(f"✅ Would remove {selected_ip} from whitelist")
                            st.info("💡 Restart controller to apply changes")
                    
                    with remove_col2:
                        if selected_ip in blacklist and st.button("➖ Remove from Blacklist", key="remove_blacklist"):
                            st.success(f"✅ Would remove {selected_ip} from blacklist")
                            st.info("💡 Restart controller to apply changes")
                    
                    with remove_col3:
                        if selected_ip in honeypot_ips and st.button("➖ Remove from Honeypot", key="remove_honeypot"):
                            st.success(f"✅ Would remove {selected_ip} from honeypot list")
                            st.info("💡 Edit mitigation_manager.py manually and restart")
            else:
                st.info("No IPs currently monitored")

    elif tab == "🎯 Threat Intelligence":
        st.header("🎯 Enhanced Threat Intelligence")
        st.markdown("---")
        if not mitigation_df.empty:
            # Build source risk stats
            mitigation_df['risk_score'] = mitigation_df['risk_score'].astype(float)
            mitigation_df['honeypot_hit'] = mitigation_df['details'].str.upper().str.contains('HONEYPOT', na=False)
            grouped = mitigation_df.groupby('source_ip').agg(
                max_risk=('risk_score', 'max'),
                avg_risk=('risk_score', 'mean'),
                high_risk_events=('risk_score', lambda x: (x >= 0.4).sum()),
                blocks=('action_type', lambda x: x.isin(['SHORT_TIMEOUT_BLOCK', 'BLOCK']).sum()),
                honeypot_hits=('honeypot_hit', 'sum'),
                total_events=('risk_score', 'count')
            ).reset_index()
            top_sources = grouped.sort_values(['honeypot_hits', 'max_risk', 'high_risk_events'], ascending=False).head(10)
            
            st.markdown("### 🎯 Top Threat Sources")
            st.dataframe(
                top_sources,
                use_container_width=True,
                column_config={
                    "source_ip": st.column_config.TextColumn("Source IP"),
                    "max_risk": st.column_config.NumberColumn("Max Risk", format="%.3f"),
                    "avg_risk": st.column_config.NumberColumn("Avg Risk", format="%.3f"),
                    "high_risk_events": st.column_config.NumberColumn("High Risk Events"),
                    "blocks": st.column_config.NumberColumn("Blocks"),
                    "honeypot_hits": st.column_config.NumberColumn("Honeypot Hits"),
                    "total_events": st.column_config.NumberColumn("Total Events")
                }
            )
        else:
            st.info("No threat intelligence data available")

    elif tab == "� Analytics & Reports":
        st.header("📈 Security Analytics & Reports")
        st.markdown("---")
        if not mitigation_df.empty:
            recent = mitigation_df.tail(20)
            st.markdown("### 📋 Recent Security Activities")
            st.dataframe(
                recent[['timestamp', 'action_type', 'source_ip', 'risk_score', 'risk_level', 'details']],
                use_container_width=True,
                column_config={
                    "timestamp": st.column_config.DatetimeColumn("Timestamp"),
                    "action_type": st.column_config.TextColumn("Action"),
                    "source_ip": st.column_config.TextColumn("Source IP"),
                    "risk_score": st.column_config.NumberColumn("Risk Score", format="%.3f"),
                    "risk_level": st.column_config.TextColumn("Risk Level"),
                    "details": st.column_config.TextColumn("Details")
                }
            )
        else:
            st.info("No analytics data available")

    elif tab == "🔍 Source Investigation":
        st.header("🔍 Detailed Source Investigation")
        st.markdown("---")
        if not mitigation_df.empty:
            source_ips = mitigation_df['source_ip'].dropna().unique().tolist()
            selected_ip = st.selectbox("🎯 Select Source IP for Investigation", source_ips)
            
            if selected_ip:
                source_actions = mitigation_df[mitigation_df['source_ip'] == selected_ip]
                if not source_actions.empty:
                    # Investigation summary
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Total Events", len(source_actions))
                    with col2:
                        st.metric("First Seen", source_actions.iloc[0]['timestamp'][:19])
                    with col3:
                        st.metric("Last Seen", source_actions.iloc[-1]['timestamp'][:19])
                    with col4:
                        risk_scores = pd.to_numeric(source_actions['risk_score'], errors='coerce')
                        st.metric("Avg Risk", f"{risk_scores.mean():.3f}")
                    
                    st.markdown("---")
                    
                    # Action breakdown
                    st.markdown("### 📊 Action Breakdown")
                    action_counts = source_actions['action_type'].value_counts()
                    st.dataframe(action_counts.to_frame('Count'), use_container_width=True)
                    
                    # Recent activity
                    st.markdown("### 🕒 Recent Activity (Last 10 events)")
                    st.dataframe(
                        source_actions[['timestamp', 'action_type', 'risk_score', 'risk_level', 'details']].tail(10),
                        use_container_width=True
                    )
        else:
            st.info("No source data available for investigation")

    # Professional footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; padding: 20px; background: linear-gradient(90deg, #f8f9fa 0%, #e9ecef 100%); border-radius: 10px; margin-top: 2rem;">
        <p style="margin: 0; color: #666; font-size: 0.9rem;">
            🛡️ <strong>SDN Security Operations Center</strong> | 
            🔄 Auto-refresh: {auto_refresh}s | 
            📊 Powered by ML-driven threat detection | 
            🚀 Built with Streamlit
        </p>
        <p style="margin: 5px 0 0 0; color: #999; font-size: 0.8rem;">
            💡 <strong>Pro Tip:</strong> Use the refresh button or wait for auto-refresh to see the latest security data
        </p>
    </div>
    """.format(auto_refresh=AUTO_REFRESH_MS//1000), unsafe_allow_html=True)

if __name__ == "__main__":
    main()
