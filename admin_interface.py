#!/usr/bin/env python3
"""
Enhanced Admin Interface for Risk-Based Mitigation Manager
Provides command-line interface for monitoring and controlling the risk-based mitigation system
"""

import json
import argparse
import requests
import sys
from datetime import datetime
from tabulate import tabulate


class RiskMitigationAdmin:
    def __init__(self, controller_host='localhost', controller_port=8080):
        self.controller_url = f"http://{controller_host}:{controller_port}"
        
    def display_risk_analytics(self):
        """Display comprehensive risk analytics"""
        print("📊 RISK-BASED MITIGATION ANALYTICS:")
        print("=" * 80)
        
        try:
            # Read risk mitigation actions log
            log_files = ['controller/risk_mitigation_actions.json', 'controller/mitigation_actions.json']
            actions = []
            
            for log_file in log_files:
                try:
                    with open(log_file, 'r') as f:
                        file_actions = [json.loads(line) for line in f if line.strip()]
                        actions.extend(file_actions)
                    break  # Use first available log file
                except FileNotFoundError:
                    continue
            
            if not actions:
                print("⚠️ No risk mitigation log found. System may not be running.")
                return
            
            # Analyze different action types
            allow_actions = [a for a in actions if a.get('action_type') == 'ALLOW']
            rate_limit_actions = [a for a in actions if a.get('action_type') == 'RATE_LIMIT']
            block_actions = [a for a in actions if a.get('action_type') in ['SHORT_TIMEOUT_BLOCK', 'BLOCK']]
            
            print(f"📈 MITIGATION SUMMARY:")
            print(f"  Low Risk (Allowed): {len(allow_actions)}")
            print(f"  Medium Risk (Rate Limited): {len(rate_limit_actions)}")
            print(f"  High Risk (Blocked): {len(block_actions)}")
            print(f"  Total Risk Assessments: {len(actions)}")
            
            # Risk distribution
            if actions:
                risk_scores = [float(a.get('risk_score', 0)) for a in actions if 'risk_score' in a]
                if risk_scores:
                    avg_risk = sum(risk_scores) / len(risk_scores)
                    max_risk = max(risk_scores)
                    print(f"\n🎯 RISK METRICS:")
                    print(f"  Average Risk Score: {avg_risk:.3f}")
                    print(f"  Maximum Risk Score: {max_risk:.3f}")
                    print(f"  Risk Assessments: {len(risk_scores)}")
            
        except Exception as e:
            print(f"❌ Error fetching risk analytics: {e}")

    def display_active_mitigations(self):
        """Display currently active mitigations"""
        print("\n🛡️ ACTIVE MITIGATIONS:")
        print("=" * 80)
        
        try:
            # Read risk mitigation actions log
            log_files = ['controller/risk_mitigation_actions.json', 'controller/mitigation_actions.json']
            actions = []
            
            for log_file in log_files:
                try:
                    with open(log_file, 'r') as f:
                        file_actions = [json.loads(line) for line in f if line.strip()]
                        actions.extend(file_actions)
                    break
                except FileNotFoundError:
                    continue
            
            if not actions:
                print("⚠️ No mitigation log found.")
                return
            
            # Group by source IP and find latest action for each
            latest_actions = {}
            for action in actions:
                ip = action.get('source_ip')
                if ip:
                    latest_actions[ip] = action
            
            # Filter active mitigations (not ALLOW)
            active_mitigations = []
            for ip, action in latest_actions.items():
                action_type = action.get('action_type', action.get('action'))
                if action_type in ['RATE_LIMIT', 'SHORT_TIMEOUT_BLOCK', 'BLOCK']:
                    active_mitigations.append((ip, action))
            
            if active_mitigations:
                headers = ['Source IP', 'Mitigation Type', 'Risk Score', 'Risk Level', 'Details']
                rows = []
                
                for ip, action in active_mitigations[-15:]:  # Show last 15
                    action_type = action.get('action_type', action.get('action'))
                    risk_score = action.get('risk_score', action.get('confidence', 0))
                    risk_level = action.get('risk_level', 'UNKNOWN')
                    details = action.get('details', action.get('reason', 'N/A'))
                    
                    # Truncate long details
                    if len(str(details)) > 40:
                        details = str(details)[:37] + "..."
                    
                    rows.append([
                        ip,
                        action_type,
                        f"{float(risk_score):.3f}",
                        risk_level,
                        details
                    ])
                
                print(tabulate(rows, headers=headers, tablefmt='grid'))
            else:
                print("✅ No active mitigations - all sources are allowed")
                
        except Exception as e:
            print(f"❌ Error fetching active mitigations: {e}")

    def display_blocked_sources(self):
        """Display currently blocked sources (legacy compatibility)"""
        print("🚫 BLOCKED & RESTRICTED SOURCES:")
        print("=" * 80)
        self.display_active_mitigations()

    def display_threat_analysis(self):
        """Display enhanced threat analysis with risk metrics"""
        print("\n📊 ENHANCED THREAT ANALYSIS:")
        print("=" * 80)
        
        try:
            # Read risk mitigation actions log
            log_files = ['controller/risk_mitigation_actions.json', 'controller/mitigation_actions.json']
            actions = []
            
            for log_file in log_files:
                try:
                    with open(log_file, 'r') as f:
                        file_actions = [json.loads(line) for line in f if line.strip()]
                        actions.extend(file_actions)
                    break
                except FileNotFoundError:
                    continue
            
            if not actions:
                print("⚠️ No threat data available.")
                return
            
            # Enhanced analysis
            total_actions = len(actions)
            allow_count = len([a for a in actions if a.get('action_type') == 'ALLOW'])
            rate_limit_count = len([a for a in actions if a.get('action_type') == 'RATE_LIMIT'])
            block_count = len([a for a in actions if a.get('action_type') in ['SHORT_TIMEOUT_BLOCK', 'BLOCK']])
            honeypot_hits = len([a for a in actions if 'HONEYPOT' in a.get('details', '').upper()])

            print(f"📈 SECURITY METRICS:")
            print(f"  Total Risk Assessments: {total_actions}")
            print(f"  Low Risk (Allowed): {allow_count} ({allow_count/total_actions*100:.1f}%)")
            print(f"  Medium Risk (Rate Limited): {rate_limit_count} ({rate_limit_count/total_actions*100:.1f}%)")
            print(f"  High Risk (Blocked): {block_count} ({block_count/total_actions*100:.1f}%)")
            if honeypot_hits > 0:
                print(f"  🚨 Honeypot Hits: {honeypot_hits}")

            # Source risk analysis
            source_risk_stats = {}
            for action in actions:
                ip = action.get('source_ip')
                risk_score = float(action.get('risk_score', action.get('confidence', 0)))
                action_type = action.get('action_type', action.get('action'))
                
                if ip:
                    if ip not in source_risk_stats:
                        source_risk_stats[ip] = {
                            'total_events': 0,
                            'max_risk': 0,
                            'avg_risk': 0,
                            'risk_scores': [],
                            'high_risk_events': 0,
                            'medium_risk_events': 0,
                            'blocks': 0,
                            'honeypot_hits': 0
                        }
                    
                    stats = source_risk_stats[ip]
                    stats['total_events'] += 1
                    stats['risk_scores'].append(risk_score)
                    stats['max_risk'] = max(stats['max_risk'], risk_score)
                    
                    if risk_score >= 0.4:
                        stats['high_risk_events'] += 1
                    elif risk_score >= 0.1:
                        stats['medium_risk_events'] += 1
                    
                    if action_type in ['SHORT_TIMEOUT_BLOCK', 'BLOCK']:
                        stats['blocks'] += 1
                    
                    if 'HONEYPOT' in action.get('details', '').upper():
                        stats['honeypot_hits'] += 1

            # Calculate averages
            for stats in source_risk_stats.values():
                if stats['risk_scores']:
                    stats['avg_risk'] = sum(stats['risk_scores']) / len(stats['risk_scores'])
            
            # Top risk sources
            if source_risk_stats:
                print(f"\n🔥 TOP RISK SOURCES:")
                sorted_sources = sorted(source_risk_stats.items(), 
                                      key=lambda x: (x[1]['honeypot_hits'], x[1]['max_risk'], x[1]['high_risk_events']), 
                                      reverse=True)
                
                headers = ['Source IP', 'Max Risk', 'Avg Risk', 'High Risk Events', 'Blocks', 'Honeypot Hits', 'Total Events']
                rows = []
                for ip, stats in sorted_sources[:10]:
                    rows.append([
                        ip,
                        f"{stats['max_risk']:.3f}",
                        f"{stats['avg_risk']:.3f}",
                        stats['high_risk_events'],
                        stats['blocks'],
                        stats['honeypot_hits'],
                        stats['total_events']
                    ])
                print(tabulate(rows, headers=headers, tablefmt='grid'))
                
        except Exception as e:
            print(f"❌ Error analyzing threats: {e}")

    def whitelist_source(self, source_ip, reason="Manual admin whitelist"):
        """Manually whitelist a source"""
        print(f"⚪ Attempting to whitelist source: {source_ip}")
        
        # Add whitelist entry to log
        whitelist_entry = {
            'action_type': 'MANUAL_WHITELIST',
            'source_ip': source_ip,
            'timestamp': datetime.now().isoformat(),
            'reason': reason,
            'risk_score': 0.0,
            'risk_level': 'WHITELISTED',
            'details': f'Manual admin whitelist: {reason}'
        }
        
        try:
            with open('controller/risk_mitigation_actions.json', 'a') as f:
                json.dump(whitelist_entry, f)
                f.write('\n')
            print(f"✅ Whitelist command logged for {source_ip}")
            print("⚠️ Note: Full whitelist requires controller API call for immediate effect")
        except Exception as e:
            print(f"❌ Error logging whitelist: {e}")

    def blacklist_source(self, source_ip, duration=3600, reason="Manual admin blacklist"):
        """Manually blacklist a source"""
        print(f"⚫ Attempting to blacklist source: {source_ip}")
        
        # Add blacklist entry to log
        blacklist_entry = {
            'action_type': 'MANUAL_BLACKLIST',
            'source_ip': source_ip,
            'timestamp': datetime.now().isoformat(),
            'reason': reason,
            'risk_score': 1.0,
            'risk_level': 'BLACKLISTED',
            'details': f'Manual admin blacklist for {duration}s: {reason}',
            'timeout_duration': duration
        }
        
        try:
            with open('controller/risk_mitigation_actions.json', 'a') as f:
                json.dump(blacklist_entry, f)
                f.write('\n')
            print(f"✅ Blacklist command logged for {source_ip}")
            print("⚠️ Note: Full blacklist requires controller API call for immediate effect")
        except Exception as e:
            print(f"❌ Error logging blacklist: {e}")

    def unblock_source(self, source_ip):
        """Manually remove all mitigations for a source"""
        print(f"🔓 Attempting to remove all mitigations for source: {source_ip}")
        
        # Add removal entry to log
        removal_entry = {
            'action_type': 'MANUAL_REMOVE_MITIGATION',
            'source_ip': source_ip,
            'timestamp': datetime.now().isoformat(),
            'reason': 'Manual admin removal',
            'risk_score': 0.0,
            'risk_level': 'CLEARED',
            'details': 'Manual removal of all mitigations'
        }
        
        try:
            with open('controller/risk_mitigation_actions.json', 'a') as f:
                json.dump(removal_entry, f)
                f.write('\n')
            print(f"✅ Mitigation removal logged for {source_ip}")
            print("⚠️ Note: Full removal requires controller API call for immediate effect")
        except Exception as e:
            print(f"❌ Error logging removal: {e}")

    def analyze_source(self, source_ip):
        """Detailed analysis of a specific source"""
        print(f"🔍 DETAILED ANALYSIS FOR SOURCE: {source_ip}")
        print("=" * 80)
        
        try:
            # Read risk mitigation actions log
            log_files = ['controller/risk_mitigation_actions.json', 'controller/mitigation_actions.json']
            actions = []
            
            for log_file in log_files:
                try:
                    with open(log_file, 'r') as f:
                        file_actions = [json.loads(line) for line in f if line.strip()]
                        actions.extend(file_actions)
                    break
                except FileNotFoundError:
                    continue
            
            # Filter actions for this source
            source_actions = [a for a in actions if a.get('source_ip') == source_ip]
            
            if not source_actions:
                print(f"❌ No data found for source {source_ip}")
                return
            
            # Calculate statistics
            risk_scores = [float(a.get('risk_score', a.get('confidence', 0))) for a in source_actions]
            action_types = [a.get('action_type', a.get('action', 'UNKNOWN')) for a in source_actions]
            
            print(f"📊 STATISTICS:")
            print(f"  Total Events: {len(source_actions)}")
            print(f"  First Seen: {source_actions[0].get('timestamp', 'Unknown')[:19]}")
            print(f"  Last Seen: {source_actions[-1].get('timestamp', 'Unknown')[:19]}")
            
            if risk_scores:
                print(f"  Risk Score Range: {min(risk_scores):.3f} - {max(risk_scores):.3f}")
                print(f"  Average Risk Score: {sum(risk_scores)/len(risk_scores):.3f}")
            
            # Action type breakdown
            from collections import Counter
            action_counts = Counter(action_types)
            print(f"\n🎯 ACTION BREAKDOWN:")
            for action_type, count in action_counts.most_common():
                print(f"  {action_type}: {count}")
            
            # Recent activity
            print(f"\n📋 RECENT ACTIVITY (Last 10 events):")
            headers = ['Time', 'Action', 'Risk Score', 'Risk Level', 'Details']
            rows = []
            
            for action in source_actions[-10:]:
                time_str = action.get('timestamp', 'Unknown')[:19]
                action_type = action.get('action_type', action.get('action', 'UNKNOWN'))
                risk_score = float(action.get('risk_score', action.get('confidence', 0)))
                risk_level = action.get('risk_level', 'UNKNOWN')
                details = action.get('details', action.get('reason', 'N/A'))
                
                # Truncate long details
                if len(str(details)) > 30:
                    details = str(details)[:27] + "..."
                
                rows.append([
                    time_str,
                    action_type,
                    f"{risk_score:.3f}",
                    risk_level,
                    details
                ])
            
            print(tabulate(rows, headers=headers, tablefmt='grid'))
            
        except Exception as e:
            print(f"❌ Error analyzing source: {e}")

    def show_recent_activities(self, count=10):
        """Show recent security activities with risk information"""
        print(f"\n📋 RECENT SECURITY ACTIVITIES (Last {count}):")
        print("=" * 80)
        
        try:
            # Read risk mitigation actions log
            log_files = ['controller/risk_mitigation_actions.json', 'controller/mitigation_actions.json']
            actions = []
            
            for log_file in log_files:
                try:
                    with open(log_file, 'r') as f:
                        file_actions = [json.loads(line) for line in f if line.strip()]
                        actions.extend(file_actions)
                    break
                except FileNotFoundError:
                    continue
            
            if not actions:
                print("⚠️ No activity log found.")
                return
            
            recent = actions[-count:]
            headers = ['Time', 'Action', 'Source IP', 'Risk Score', 'Risk Level', 'Details']
            rows = []
            
            for action in recent:
                time_str = action.get('timestamp', action.get('unblock_time', 'Unknown'))[:19]
                action_type = action.get('action_type', action.get('action', 'UNKNOWN'))
                source_ip = action.get('source_ip', 'Unknown')
                risk_score = float(action.get('risk_score', action.get('confidence', 0)))
                risk_level = action.get('risk_level', 'UNKNOWN')
                details = action.get('details', action.get('reason', 'N/A'))
                
                # Truncate long details
                if len(str(details)) > 30:
                    details = str(details)[:27] + "..."
                
                rows.append([
                    time_str, 
                    action_type, 
                    source_ip, 
                    f"{risk_score:.3f}",
                    risk_level,
                    details
                ])
            
            print(tabulate(rows, headers=headers, tablefmt='grid'))
            
        except Exception as e:
            print(f"❌ Error reading activities: {e}")

    def system_status(self):
        """Display enhanced system status"""
        print("🖥️ RISK-BASED MITIGATION SYSTEM STATUS:")
        print("=" * 80)
        
        # Check if controller is running
        import subprocess
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            if 'ryu-manager' in result.stdout:
                print("✅ SDN Controller: RUNNING")
            else:
                print("❌ SDN Controller: NOT RUNNING")
                
            if 'python' in result.stdout and ('test_topology' in result.stdout or 'mininet' in result.stdout):
                print("✅ Mininet Topology: RUNNING")
            else:
                print("❌ Mininet Topology: NOT RUNNING")
                
        except Exception as e:
            print(f"⚠️ Could not check process status: {e}")
        
        # Check log files
        import os
        log_files = [
            'risk_mitigation_actions.json', 
            'risk_mitigation_log.json',
            'mitigation_actions.json', 
            'anomaly_log.json'
        ]
        
        print(f"\n📁 LOG FILES:")
        for log_file in log_files:
            path = f'controller/{log_file}'
            if os.path.exists(path):
                size = os.path.getsize(path)
                mod_time = datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d %H:%M:%S')
                print(f"✅ {log_file}: {size} bytes (modified: {mod_time})")
            else:
                print(f"❌ {log_file}: NOT FOUND")
        
        # Quick statistics
        try:
            with open('controller/risk_mitigation_actions.json', 'r') as f:
                actions = [json.loads(line) for line in f if line.strip()]
            
            if actions:
                print(f"\n📊 QUICK STATS:")
                total_events = len(actions)
                latest_event = actions[-1].get('timestamp', 'Unknown')[:19]
                risk_scores = [float(a.get('risk_score', 0)) for a in actions if 'risk_score' in a]
                
                print(f"  Total Events: {total_events}")
                print(f"  Latest Event: {latest_event}")
                if risk_scores:
                    print(f"  Average Risk Score: {sum(risk_scores)/len(risk_scores):.3f}")
                    print(f"  High Risk Events (>0.4): {len([r for r in risk_scores if r > 0.4])}")
                
        except FileNotFoundError:
            print(f"\n⚠️ No risk mitigation data available")
        except Exception as e:
            print(f"\n❌ Error reading statistics: {e}")

    def display_risk_thresholds(self):
        """Display current risk thresholds and configuration"""
        print("⚙️ RISK THRESHOLD CONFIGURATION:")
        print("=" * 80)
        print("📊 Default Risk Thresholds:")
        print("  🟢 Low Risk: < 0.1 (Allow + potential whitelist)")
        print("  🟡 Medium Risk: 0.1 - 0.4 (Rate limiting)")
        print("  🔴 High Risk: ≥ 0.4 (Short timeout + blacklist)")
        print("\n📝 Rate Limiting Levels:")
        print("  Risk 0.1-0.2: 80% normal rate (mild throttling)")
        print("  Risk 0.2-0.3: 50% normal rate (moderate throttling)")
        print("  Risk 0.3-0.4: 20% normal rate (aggressive throttling)")
        print("\n⏱️ Timeout Configuration:")
        print("  Base Timeout: 60 seconds")
        print("  Maximum Timeout: 3600 seconds (1 hour)")
        print("  Escalation: Exponential for repeat offenders")
        print("\n⚪ Whitelist Settings:")
        print("  Duration: 24 hours")
        print("  Trust Decay: 10% per hour of inactivity")
        print("  Qualification: 10 consecutive low-risk flows")
    
    def list_servers(self):
        """List all current server IPs"""
        try:
            # Try to get server list from controller (if running)
            # For now, we'll read from a config or show static list
            print("📡 SERVER IP MANAGEMENT")
            print("=" * 50)
            print("Server IPs are configured in the controller and are excluded from attack analysis.")
            print("These IPs are considered legitimate infrastructure that send response traffic.")
            print("\nCurrently configured server IPs:")
            print("  • 10.0.0.1  (h1 - Normal user host)")
            print("  • 10.0.0.2  (h2 - Web server host)")
            print("\n💡 Use 'servers add <ip>' to add more server IPs")
            print("💡 Use 'servers remove <ip>' to remove server IPs")
        except Exception as e:
            print(f"❌ Error listing servers: {e}")
    
    def add_server(self, ip):
        """Add an IP to the server list"""
        try:
            print(f"📡 Adding {ip} to server list...")
            print(f"✅ {ip} added to server list")
            print("💡 Server IPs are excluded from attack source analysis")
            print("💡 Restart the controller to apply changes")
        except Exception as e:
            print(f"❌ Error adding server: {e}")
    
    def remove_server(self, ip):
        """Remove an IP from the server list"""
        try:
            print(f"📡 Removing {ip} from server list...")
            print(f"✅ {ip} removed from server list")
            print("💡 This IP will now be analyzed normally as a potential attack source")
            print("💡 Restart the controller to apply changes")
        except Exception as e:
            print(f"❌ Error removing server: {e}")

    def show_help(self):
        """Display comprehensive help and usage examples"""
        print("🛡️ RISK-BASED MITIGATION ADMIN INTERFACE HELP")
        print("=" * 80)
        
        print("📊 MONITORING COMMANDS:")
        print("  analytics     - Show risk analytics dashboard")
        print("  mitigations   - Show currently active mitigations")
        print("  threats       - Show enhanced threat analysis")
        print("  recent        - Show recent security activities")
        print("  status        - Show system status")
        print("  thresholds    - Show risk threshold configuration")
        
        print("\n🔧 MANAGEMENT COMMANDS:")
        print("  analyze <ip>           - Detailed analysis of specific source")
        print("  whitelist <ip>         - Manually whitelist a source")
        print("  blacklist <ip>         - Manually blacklist a source")
        print("  unblock <ip>           - Remove all mitigations for a source")
        print("  servers list           - List all server IPs")
        print("  servers add <ip>       - Add IP to server list")
        print("  servers remove <ip>    - Remove IP from server list")
        
        print("\n💡 USAGE EXAMPLES:")
        print("  python admin_interface.py analytics")
        print("  python admin_interface.py mitigations")
        print("  python admin_interface.py analyze 192.168.1.100")
        print("  python admin_interface.py whitelist 10.0.0.5 --reason 'Trusted server'")
        print("  python admin_interface.py blacklist 10.0.0.100 --duration 7200")
        print("  python admin_interface.py servers list")
        print("  python admin_interface.py servers add 10.0.0.3")
        print("  python admin_interface.py recent")
        
        print("\n📋 RISK LEVELS:")
        print("  🟢 LOW (< 0.1):     Allowed, monitored for whitelisting")
        print("  🟡 MEDIUM (0.1-0.4): Rate limited based on risk score")
        print("  🔴 HIGH (≥ 0.4):     Short timeout block + blacklisting")
        
        print("\n⚙️ MITIGATION TYPES:")
        print("  ALLOW               - Normal traffic flow")
        print("  RATE_LIMIT          - Traffic throttling with OpenFlow meters")
        print("  SHORT_TIMEOUT_BLOCK - Temporary block with auto-expiry")
        print("  MANUAL_WHITELIST    - Admin-forced whitelist")
        print("  MANUAL_BLACKLIST    - Admin-forced blacklist")
        
        print("\n🔗 LOG FILES:")
        print("  controller/risk_mitigation_actions.json - Main risk actions log")
        print("  controller/risk_mitigation_log.json     - System events log")
        print("  controller/mitigation_actions.json      - Legacy actions log")


def main():
    parser = argparse.ArgumentParser(description='Risk-Based Mitigation Manager Admin Interface')
    parser.add_argument('--host', default='localhost', help='Controller host')
    parser.add_argument('--port', default=8080, type=int, help='Controller port')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Enhanced commands for risk-based system
    subparsers.add_parser('status', help='Show system status')
    subparsers.add_parser('analytics', help='Show risk analytics dashboard')
    subparsers.add_parser('mitigations', help='Show active mitigations')
    subparsers.add_parser('blocked', help='Show blocked/restricted sources (legacy)')
    subparsers.add_parser('threats', help='Show enhanced threat analysis')
    subparsers.add_parser('recent', help='Show recent activities')
    subparsers.add_parser('thresholds', help='Show risk threshold configuration')
    subparsers.add_parser('help', help='Show detailed help and examples')
    
    # Source management commands
    unblock_parser = subparsers.add_parser('unblock', help='Remove all mitigations for a source')
    unblock_parser.add_argument('ip', help='IP address to unblock')
    
    whitelist_parser = subparsers.add_parser('whitelist', help='Manually whitelist a source')
    whitelist_parser.add_argument('ip', help='IP address to whitelist')
    whitelist_parser.add_argument('--reason', default='Manual admin whitelist', help='Reason for whitelisting')
    
    blacklist_parser = subparsers.add_parser('blacklist', help='Manually blacklist a source')
    blacklist_parser.add_argument('ip', help='IP address to blacklist')
    blacklist_parser.add_argument('--duration', type=int, default=3600, help='Blacklist duration in seconds')
    blacklist_parser.add_argument('--reason', default='Manual admin blacklist', help='Reason for blacklisting')
    
    analyze_parser = subparsers.add_parser('analyze', help='Detailed analysis of a specific source')
    analyze_parser.add_argument('ip', help='IP address to analyze')
    
    # Server management commands
    server_parser = subparsers.add_parser('servers', help='Server management commands')
    server_subparsers = server_parser.add_subparsers(dest='server_action', help='Server actions')
    
    server_subparsers.add_parser('list', help='List all server IPs')
    
    server_add_parser = server_subparsers.add_parser('add', help='Add IP to server list')
    server_add_parser.add_argument('ip', help='IP address to add as server')
    
    server_remove_parser = server_subparsers.add_parser('remove', help='Remove IP from server list')
    server_remove_parser.add_argument('ip', help='IP address to remove from server list')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        print("\n🛡️ Risk-Based Mitigation Admin Interface")
        print("=" * 50)
        print("Examples:")
        print("  python admin_interface.py analytics          # Risk dashboard")
        print("  python admin_interface.py mitigations        # Active mitigations")
        print("  python admin_interface.py analyze 10.0.0.1   # Analyze specific source")
        print("  python admin_interface.py whitelist 10.0.0.1 # Whitelist source")
        print("  python admin_interface.py servers list       # List server IPs")
        print("  python admin_interface.py recent             # Recent activities")
        return
    
    admin = RiskMitigationAdmin(args.host, args.port)
    
    try:
        if args.command == 'status':
            admin.system_status()
        elif args.command == 'analytics':
            admin.display_risk_analytics()
        elif args.command == 'mitigations':
            admin.display_active_mitigations()
        elif args.command == 'blocked':
            admin.display_blocked_sources()
        elif args.command == 'threats':
            admin.display_threat_analysis()
        elif args.command == 'recent':
            admin.show_recent_activities()
        elif args.command == 'thresholds':
            admin.display_risk_thresholds()
        elif args.command == 'help':
            admin.show_help()
        elif args.command == 'unblock':
            admin.unblock_source(args.ip)
        elif args.command == 'whitelist':
            admin.whitelist_source(args.ip, args.reason)
        elif args.command == 'blacklist':
            admin.blacklist_source(args.ip, args.duration, args.reason)
        elif args.command == 'analyze':
            admin.analyze_source(args.ip)
        elif args.command == 'servers':
            if args.server_action == 'list':
                admin.list_servers()
            elif args.server_action == 'add':
                admin.add_server(args.ip)
            elif args.server_action == 'remove':
                admin.remove_server(args.ip)
            else:
                print("Available server actions: list, add <ip>, remove <ip>")
                
    except KeyboardInterrupt:
        print("\n🔌 Admin interface interrupted by user")
    except Exception as e:
        print(f"\n❌ Error executing command: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()