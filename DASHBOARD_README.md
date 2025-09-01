# 🛡️ SDN Security Operations Center Dashboard

A professional, real-time analytics dashboard for monitoring and managing the ML-driven SDN security system.

## ✨ Enhanced Features

### 🏠 Executive Dashboard
- **Professional KPI Metrics**: Real-time security metrics with visual indicators
- **Security Status Overview**: System health monitoring with color-coded alerts
- **Interactive Charts**: Risk distribution, timeline analysis, and threat visualizations
- **24-Hour Activity Summary**: Recent security events and trends

### 🛡️ Active Mitigations
- **Real-time Mitigation Monitoring**: Current active security measures
- **Advanced Filtering**: Filter by action type and risk threshold
- **Enhanced Data Display**: Professional table formatting with helpful tooltips

### ⚙️ System Configuration
- **IP List Management**: Visual management of whitelist, blacklist, and honeypot IPs
- **Conflict Resolution**: Automatic handling of IP list conflicts
- **Admin Controls**: Add/remove IPs with validation (preview mode)
- **Configuration Summary**: Quick overview of all monitored IPs

### 🎯 Threat Intelligence
- **Advanced Source Analysis**: Detailed threat actor profiling
- **Risk Scoring**: Comprehensive risk assessment metrics
- **Honeypot Detection**: Special handling for honeypot interactions

### 📈 Analytics & Reports
- **Historical Analysis**: Recent security activities and trends
- **Professional Reporting**: Enhanced data presentation with proper formatting

### 🔍 Source Investigation
- **Deep Dive Analysis**: Detailed investigation of specific IP addresses
- **Activity Timeline**: Historical view of source behavior
- **Risk Profiling**: Comprehensive risk assessment per source

## 🚀 Professional Enhancements

### Visual Improvements
- **Modern UI Design**: Gradient backgrounds, professional color schemes
- **Interactive Charts**: Plotly-powered visualizations with hover effects
- **Responsive Layout**: Optimized for different screen sizes
- **Professional Typography**: Enhanced fonts and spacing

### Data Presentation
- **Enhanced Metrics**: Color-coded KPIs with delta indicators
- **Smart Tables**: Column configuration with helpful tooltips
- **Status Indicators**: Visual health monitoring
- **Professional Formatting**: Number formatting and data validation

### User Experience
- **Auto-refresh**: Configurable automatic data updates
- **Navigation**: Enhanced sidebar with icons and descriptions
- **Help Text**: Tooltips and explanations throughout
- **Error Handling**: Graceful fallbacks when data is unavailable

## 📊 Charts and Visualizations

### Interactive Charts (Plotly)
1. **Risk Distribution Donut Chart**: Visual breakdown of security actions
2. **Timeline Analysis**: Hourly security events with trend lines
3. **Risk Score Histogram**: Distribution of risk scores with thresholds
4. **Top Sources Bar Chart**: Most active threat sources with risk coloring

### Fallback Charts (Streamlit)
- Automatic fallback to built-in charts when Plotly is unavailable
- Ensures dashboard functionality in all environments

## 🛠️ Installation & Setup

### Prerequisites
```bash
pip install streamlit plotly streamlit-autorefresh pandas numpy
```

### Quick Start
```bash
# Option 1: Use the launcher script
./run_dashboard.sh

# Option 2: Run directly
streamlit run analytics_dashboard.py

# Option 3: Custom configuration
streamlit run analytics_dashboard.py --server.port 8501 --server.address 0.0.0.0
```

### Configuration
- **Auto-refresh interval**: Modify `AUTO_REFRESH_MS` in the script (default: 3 seconds)
- **Data paths**: Update `CONTROLLER_DIR` if your controller files are elsewhere
- **Port**: Default is 8501, change in launcher script if needed

## 📁 Data Sources

The dashboard monitors these files:
- `controller/anomaly_log.json` - ML model predictions and anomaly detection
- `controller/risk_mitigation_actions.json` - Current mitigation actions
- `controller/mitigation_actions.json` - Legacy mitigation log
- `controller/ryu_controller.py` - Controller configuration (whitelist extraction)
- `controller/mitigation_manager.py` - Mitigation configuration (honeypot IPs)

## 🔧 Technical Details

### Architecture
- **Frontend**: Streamlit with custom CSS styling
- **Charts**: Plotly for interactive visualizations with Streamlit fallbacks
- **Data Processing**: Pandas for data manipulation and analysis
- **Real-time Updates**: Streamlit auto-refresh with configurable intervals

### Performance
- **Efficient Data Loading**: JSON line-by-line parsing
- **Smart Caching**: Streamlit's built-in caching for better performance
- **Error Handling**: Graceful degradation when data sources are unavailable

### Security
- **Read-only Operations**: Dashboard only reads data, doesn't modify system
- **Input Validation**: IP address validation for admin controls
- **Safe Parsing**: Error handling for malformed JSON data

## 🚀 Usage Tips

### For Security Analysts
1. **Start with Executive Dashboard** - Get overall system health
2. **Monitor Active Mitigations** - Check current security measures
3. **Investigate Threats** - Use Source Investigation for deep dives
4. **Review Configuration** - Ensure IP lists are properly maintained

### For System Administrators
1. **Check System Configuration** - Verify IP lists and settings
2. **Monitor Performance** - Watch KPIs and response times
3. **Review Logs** - Use Analytics & Reports for historical analysis
4. **Manage IP Lists** - Use admin controls for list management

### For Network Engineers
1. **Analyze Traffic Patterns** - Review timeline charts and trends
2. **Tune Thresholds** - Monitor risk score distributions
3. **Optimize Performance** - Check mitigation effectiveness
4. **Plan Capacity** - Monitor event volumes and trends

## 🔄 Auto-Refresh & Real-time Monitoring

The dashboard automatically refreshes every 3 seconds by default:
- **Primary**: Uses `streamlit-autorefresh` for smooth updates
- **Fallback**: JavaScript-based refresh if autorefresh unavailable
- **Manual**: Refresh button for immediate updates
- **Configurable**: Modify refresh interval in the code

## 🎨 Customization

### Styling
- Modify CSS in the `st.markdown()` section for custom themes
- Adjust colors, fonts, and layouts to match your organization's branding
- Professional color scheme included with security-appropriate colors

### Functionality
- Add new metrics by extending the KPI calculations
- Create custom charts by adding new visualization functions
- Extend filtering options in the various tabs

## 📈 Monitoring Best Practices

1. **Regular Review**: Check the dashboard multiple times per day
2. **Trend Analysis**: Look for patterns in the timeline charts
3. **Threshold Tuning**: Adjust risk thresholds based on observed data
4. **Configuration Maintenance**: Keep IP lists updated and conflict-free
5. **Performance Monitoring**: Watch system responsiveness and data freshness

---

**🛡️ SDN Security Operations Center Dashboard** - Your comprehensive security monitoring solution.
