#!/usr/bin/env python3
"""
Admin Interface for Mitigation Manager
Provides command-line interface for monitoring and controlling the mitigation system
"""

import json
import argparse
import requests
import sys
from datetime import datetime
from tabulate import tabulate


class MitigationAdmin:
    def __init__(self, controller_host='localhost', controller_port=8080):
        self.controller_url = f"http://{controller_host}:{controller_port}"
        
    def display_blocked_sources(self):
        """Display currently blocked sources"""
        try:
            # This would typically fetch from the controller API
            # For now, reading from log files
            print("🚫 CURRENTLY BLOCKED SOURCES:")
            print("=" * 80)
            
            # Read mitigation actions log
            try:
                with open('controller/mitigation_actions.json', 'r') as f:
                    actions = [json.loads(line) for line in f if line.strip()]
                
                # Filter for current blocks
                blocked = [action for action in actions if action['action'] == 'BLOCK']
                unblocked = {action['source_ip'] for action in actions if action['action'] == 'UNBLOCK'}
                
                current_blocks = [block for block in blocked if block['source_ip'] not in unblocked]
                
                if current_blocks:
                    headers = ['Source IP', 'Blocked Since', 'Reason', 'Confidence', 'Duration (s)']
                    rows = []
                    for block in current_blocks[-10:]:  # Show last 10
                        rows.append([
                            block['source_ip'],
                            block['timestamp'][:19],  # Remove microseconds
                            block['reason'],
                            f"{block['confidence']:.3f}",
                            block['duration']
                        ])
                    print(tabulate(rows, headers=headers, tablefmt='grid'))
                else:
                    print("✅ No sources currently blocked")
                    
            except FileNotFoundError:
                print("⚠️ No mitigation log found. System may not be running.")
                
        except Exception as e:
            print(f"❌ Error fetching blocked sources: {e}")

    def display_threat_analysis(self):
        """Display threat analysis and statistics"""
        print("\n📊 THREAT ANALYSIS:")
        print("=" * 80)
        
        try:
            with open('controller/mitigation_actions.json', 'r') as f:
                actions = [json.loads(line) for line in f if line.strip()]
            
            # Analysis
            total_actions = len(actions)
            blocks = [a for a in actions if a['action'] == 'BLOCK']
            unblocks = [a for a in actions if a['action'] == 'UNBLOCK']
            suspicious = [a for a in actions if a['action'] == 'SUSPICIOUS']
            
            # Source statistics
            source_stats = {}
            for action in actions:
                ip = action['source_ip']
                if ip not in source_stats:
                    source_stats[ip] = {'blocks': 0, 'suspicious': 0, 'total': 0}
                source_stats[ip]['total'] += 1
                if action['action'] == 'BLOCK':
                    source_stats[ip]['blocks'] += 1
                elif action['action'] == 'SUSPICIOUS':
                    source_stats[ip]['suspicious'] += 1
            
            # Display statistics
            print(f"Total Security Events: {total_actions}")
            print(f"Blocks Issued: {len(blocks)}")
            print(f"Unblocks Issued: {len(unblocks)}")
            print(f"Suspicious Activities: {len(suspicious)}")
            print(f"Unique Sources: {len(source_stats)}")
            
            # Top threat sources
            if source_stats:
                print("\n🔥 TOP THREAT SOURCES:")
                sorted_sources = sorted(source_stats.items(), 
                                      key=lambda x: x[1]['blocks'] + x[1]['suspicious'], 
                                      reverse=True)
                headers = ['Source IP', 'Total Events', 'Blocks', 'Suspicious']
                rows = []
                for ip, stats in sorted_sources[:5]:
                    rows.append([ip, stats['total'], stats['blocks'], stats['suspicious']])
                print(tabulate(rows, headers=headers, tablefmt='grid'))
                
        except FileNotFoundError:
            print("⚠️ No security events logged yet.")
        except Exception as e:
            print(f"❌ Error analyzing threats: {e}")

    def unblock_source(self, source_ip):
        """Manually unblock a source"""
        print(f"🔓 Attempting to unblock source: {source_ip}")
        
        # In a real implementation, this would call the controller API
        # For now, we'll add an unblock entry to the log
        unblock_entry = {
            'action': 'UNBLOCK',
            'source_ip': source_ip,
            'unblock_time': datetime.now().isoformat(),
            'reason': 'Manual admin unblock',
            'original_block_reason': 'Unknown'
        }
        
        try:
            with open('controller/mitigation_actions.json', 'a') as f:
                json.dump(unblock_entry, f)
                f.write('\n')
            print(f"✅ Unblock command logged for {source_ip}")
            print("⚠️ Note: Full unblock requires controller restart or API call")
        except Exception as e:
            print(f"❌ Error logging unblock: {e}")

    def show_recent_activities(self, count=10):
        """Show recent security activities"""
        print(f"\n📋 RECENT SECURITY ACTIVITIES (Last {count}):")
        print("=" * 80)
        
        try:
            with open('controller/mitigation_actions.json', 'r') as f:
                actions = [json.loads(line) for line in f if line.strip()]
            
            recent = actions[-count:]
            headers = ['Time', 'Action', 'Source IP', 'Reason/Confidence']
            rows = []
            
            for action in recent:
                time_str = action.get('timestamp', action.get('unblock_time', 'Unknown'))[:19]
                action_type = action['action']
                source_ip = action['source_ip']
                
                if action_type == 'BLOCK':
                    detail = f"{action['reason']} (Conf: {action['confidence']:.3f})"
                elif action_type == 'UNBLOCK':
                    detail = action['reason']
                else:  # SUSPICIOUS
                    detail = f"Confidence: {action['confidence']:.3f}"
                
                rows.append([time_str, action_type, source_ip, detail])
            
            print(tabulate(rows, headers=headers, tablefmt='grid'))
            
        except FileNotFoundError:
            print("⚠️ No activity log found.")
        except Exception as e:
            print(f"❌ Error reading activities: {e}")

    def system_status(self):
        """Display system status"""
        print("🖥️ MITIGATION SYSTEM STATUS:")
        print("=" * 80)
        
        # Check if controller is running
        import subprocess
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            if 'ryu-manager' in result.stdout:
                print("✅ SDN Controller: RUNNING")
            else:
                print("❌ SDN Controller: NOT RUNNING")
                
            if 'python' in result.stdout and 'test_topology' in result.stdout:
                print("✅ Mininet Topology: RUNNING")
            else:
                print("❌ Mininet Topology: NOT RUNNING")
                
        except Exception as e:
            print(f"⚠️ Could not check process status: {e}")
        
        # Check log files
        import os
        log_files = ['mitigation_actions.json', 'anomaly_log.json']
        for log_file in log_files:
            path = f'controller/{log_file}'
            if os.path.exists(path):
                size = os.path.getsize(path)
                print(f"✅ {log_file}: {size} bytes")
            else:
                print(f"❌ {log_file}: NOT FOUND")


def main():
    parser = argparse.ArgumentParser(description='Mitigation Manager Admin Interface')
    parser.add_argument('--host', default='localhost', help='Controller host')
    parser.add_argument('--port', default=8080, type=int, help='Controller port')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Commands
    subparsers.add_parser('status', help='Show system status')
    subparsers.add_parser('blocked', help='Show blocked sources')
    subparsers.add_parser('threats', help='Show threat analysis')
    subparsers.add_parser('recent', help='Show recent activities')
    
    unblock_parser = subparsers.add_parser('unblock', help='Unblock a source')
    unblock_parser.add_argument('ip', help='IP address to unblock')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    admin = MitigationAdmin(args.host, args.port)
    
    if args.command == 'status':
        admin.system_status()
    elif args.command == 'blocked':
        admin.display_blocked_sources()
    elif args.command == 'threats':
        admin.display_threat_analysis()
    elif args.command == 'recent':
        admin.show_recent_activities()
    elif args.command == 'unblock':
        admin.unblock_source(args.ip)


if __name__ == '__main__':
    main()