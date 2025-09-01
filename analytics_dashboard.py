# --- Streamlit Dynamic Dashboard Version ---
import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime, timedelta

st.set_page_config(page_title="SDN Mitigation Analytics Dashboard", layout="wide")

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

def main():
    st.title("🛡️ SDN ML-Driven Adaptive QoS Mitigation Dashboard")
    st.caption("Real-time monitoring and analytics of the risk-based mitigation system")

    refresh = st.button("🔄 Refresh Data")
    anomaly_data, mitigation_data = load_data()
    anomaly_df = pd.DataFrame(anomaly_data)
    mitigation_df = pd.DataFrame(mitigation_data)

    tab = st.sidebar.radio("Select View", [
        "Analytics Summary",
        "Active Mitigations", 
        "IP Lists & Config",
        "Threat Analysis",
        "Recent Activities",
        "Source Analysis"
    ])

    if tab == "Analytics Summary":
        st.header("📊 Risk Analytics Summary")
        allow_actions = mitigation_df[mitigation_df['action_type'] == 'ALLOW'] if 'action_type' in mitigation_df else pd.DataFrame()
        rate_limit_actions = mitigation_df[mitigation_df['action_type'] == 'RATE_LIMIT'] if 'action_type' in mitigation_df else pd.DataFrame()
        block_actions = mitigation_df[mitigation_df['action_type'].isin(['SHORT_TIMEOUT_BLOCK', 'BLOCK'])] if 'action_type' in mitigation_df else pd.DataFrame()
        st.write(f"Low Risk (Allowed): {len(allow_actions)}")
        st.write(f"Medium Risk (Rate Limited): {len(rate_limit_actions)}")
        st.write(f"High Risk (Blocked): {len(block_actions)}")
        st.write(f"Total Risk Assessments: {len(mitigation_df)}")
        if not mitigation_df.empty and 'risk_score' in mitigation_df:
            st.write(f"Average Risk Score: {mitigation_df['risk_score'].astype(float).mean():.3f}")
            st.write(f"Maximum Risk Score: {mitigation_df['risk_score'].astype(float).max():.3f}")

    elif tab == "Active Mitigations":
        st.header("🛡️ Active Mitigations")
        if not mitigation_df.empty:
            latest_actions = mitigation_df.drop_duplicates('source_ip', keep='last')
            active = latest_actions[latest_actions['action_type'].isin(['RATE_LIMIT', 'SHORT_TIMEOUT_BLOCK', 'BLOCK'])]
            if not active.empty:
                st.dataframe(active[['source_ip', 'action_type', 'risk_score', 'risk_level', 'details']].tail(15), use_container_width=True)
            else:
                st.success("No active mitigations - all sources are allowed")

    elif tab == "IP Lists & Config":
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

    elif tab == "Threat Analysis":
        st.header("📊 Enhanced Threat Analysis")
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
            st.dataframe(top_sources, use_container_width=True)

    elif tab == "Recent Activities":
        st.header("📋 Recent Security Activities")
        if not mitigation_df.empty:
            recent = mitigation_df.tail(20)
            st.dataframe(recent[['timestamp', 'action_type', 'source_ip', 'risk_score', 'risk_level', 'details']], use_container_width=True)

    elif tab == "Source Analysis":
        st.header("🔍 Detailed Source Analysis")
        if not mitigation_df.empty:
            source_ips = mitigation_df['source_ip'].dropna().unique().tolist()
            selected_ip = st.selectbox("Select Source IP", source_ips)
            source_actions = mitigation_df[mitigation_df['source_ip'] == selected_ip]
            if not source_actions.empty:
                st.write(f"Total Events: {len(source_actions)}")
                st.write(f"First Seen: {source_actions.iloc[0]['timestamp'][:19]}")
                st.write(f"Last Seen: {source_actions.iloc[-1]['timestamp'][:19]}")
                st.write(f"Risk Score Range: {source_actions['risk_score'].astype(float).min():.3f} - {source_actions['risk_score'].astype(float).max():.3f}")
                st.write(f"Average Risk Score: {source_actions['risk_score'].astype(float).mean():.3f}")
                action_counts = source_actions['action_type'].value_counts()
                st.write("Action Breakdown:")
                st.dataframe(action_counts)
                st.write("Recent Activity (Last 10 events):")
                st.dataframe(source_actions[['timestamp', 'action_type', 'risk_score', 'risk_level', 'details']].tail(10), use_container_width=True)

    st.info("💡 TIP: Click 'Refresh Data' to update dashboard. Run with: streamlit run analytics_dashboard.py")

if __name__ == "__main__":
    main()
