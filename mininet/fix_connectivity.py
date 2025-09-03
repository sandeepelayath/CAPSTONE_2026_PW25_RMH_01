#!/usr/bin/env python3
"""
Mininet Connectivity Fix Utility
Standalone script to fix common Mininet ping and connectivity issues
"""

import subprocess
import time
import sys

def run_cmd(cmd, show_output=False):
    """Run shell command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if show_output:
            print(f"CMD: {cmd}")
            print(f"OUT: {result.stdout}")
            if result.stderr:
                print(f"ERR: {result.stderr}")
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        print(f"Error running command '{cmd}': {e}")
        return "", str(e), 1

def get_ovs_switches():
    """Get list of OVS switches"""
    stdout, stderr, rc = run_cmd("ovs-vsctl list-br")
    if rc == 0:
        return [s.strip() for s in stdout.split('\n') if s.strip()]
    return []

def get_mininet_hosts():
    """Get list of Mininet hosts from process list"""
    stdout, stderr, rc = run_cmd("ps aux | grep 'mininet:h' | grep -v grep")
    hosts = []
    for line in stdout.split('\n'):
        if 'mininet:h' in line:
            # Extract host name from process
            parts = line.split('mininet:')
            if len(parts) > 1:
                host = parts[1].split()[0]
                hosts.append(host)
    return list(set(hosts))  # Remove duplicates

def flush_ovs_flows():
    """Flush all OpenFlow flows from OVS switches"""
    print("🗑️ Flushing OpenFlow flows from all switches...")
    switches = get_ovs_switches()
    
    if not switches:
        print("❌ No OVS switches found!")
        return False
    
    for switch in switches:
        print(f"  🧹 Flushing flows on {switch}")
        run_cmd(f"ovs-ofctl del-flows {switch}")
        run_cmd(f"ovs-ofctl del-meters {switch}")
        
        # Check flow count
        stdout, _, _ = run_cmd(f"ovs-ofctl dump-flows {switch} | wc -l")
        print(f"    📊 Remaining flows: {stdout.strip()}")
    
    return True

def flush_bridge_tables():
    """Flush MAC learning tables on all bridges"""
    print("🌉 Flushing bridge MAC tables...")
    switches = get_ovs_switches()
    
    for switch in switches:
        print(f"  🧹 Flushing MAC table on {switch}")
        run_cmd(f"ovs-appctl fdb/flush {switch}")

def reset_fail_mode():
    """Reset fail mode to allow normal operation"""
    print("🔄 Resetting fail modes...")
    switches = get_ovs_switches()
    
    for switch in switches:
        print(f"  🔄 Setting {switch} to secure mode")
        run_cmd(f"ovs-vsctl set-fail-mode {switch} secure")
        run_cmd(f"ovs-vsctl set-controller {switch} tcp:127.0.0.1:6653")

def install_basic_flows():
    """Install basic connectivity flows"""
    print("📡 Installing basic connectivity flows...")
    switches = get_ovs_switches()
    
    for switch in switches:
        print(f"  📡 Installing basic flows on {switch}")
        # Allow ARP
        run_cmd(f"ovs-ofctl add-flow {switch} 'arp,priority=1000,actions=flood'")
        # Allow DHCP
        run_cmd(f"ovs-ofctl add-flow {switch} 'udp,tp_dst=67,priority=1000,actions=flood'")
        run_cmd(f"ovs-ofctl add-flow {switch} 'udp,tp_dst=68,priority=1000,actions=flood'")

def clear_host_arp():
    """Clear ARP tables on all network namespaces"""
    print("🗂️ Clearing ARP tables...")
    
    # Clear main namespace
    print("  🧹 Clearing main namespace ARP")
    run_cmd("ip neigh flush all")
    
    # Clear Mininet host namespaces
    hosts = get_mininet_hosts()
    for host in hosts:
        print(f"  🧹 Clearing ARP on {host}")
        run_cmd(f"ip netns exec {host} ip neigh flush all")

def restart_interfaces():
    """Restart network interfaces in Mininet hosts"""
    print("🔄 Restarting network interfaces...")
    hosts = get_mininet_hosts()
    
    for host in hosts:
        intf = f"{host}-eth0"
        print(f"  🔄 Restarting {intf}")
        run_cmd(f"ip netns exec {host} ip link set {intf} down")
        time.sleep(0.5)
        run_cmd(f"ip netns exec {host} ip link set {intf} up")

def emergency_learning_switch():
    """Set all switches to learning switch mode"""
    print("🚨 Setting up emergency learning switch mode...")
    switches = get_ovs_switches()
    
    for switch in switches:
        print(f"  🔄 Setting {switch} to learning mode")
        # Delete all flows
        run_cmd(f"ovs-ofctl del-flows {switch}")
        # Install flood rule
        run_cmd(f"ovs-ofctl add-flow {switch} 'priority=0,actions=flood'")
        # Set standalone mode temporarily
        run_cmd(f"ovs-vsctl set-fail-mode {switch} standalone")
    
    time.sleep(2)
    
    # Back to secure mode
    for switch in switches:
        run_cmd(f"ovs-vsctl set-fail-mode {switch} secure")

def test_connectivity():
    """Test basic connectivity"""
    print("🔍 Testing connectivity...")
    
    hosts = get_mininet_hosts()
    if len(hosts) < 2:
        print("❌ Need at least 2 hosts for connectivity test")
        return
    
    h1, h2 = hosts[0], hosts[1]
    
    # Get IP addresses
    stdout1, _, _ = run_cmd(f"ip netns exec {h1} ip addr show {h1}-eth0 | grep 'inet ' | awk '{{print $2}}' | cut -d'/' -f1")
    stdout2, _, _ = run_cmd(f"ip netns exec {h2} ip addr show {h2}-eth0 | grep 'inet ' | awk '{{print $2}}' | cut -d'/' -f1")
    
    ip1 = stdout1.strip()
    ip2 = stdout2.strip()
    
    if not ip1 or not ip2:
        print(f"❌ Could not get IPs for {h1} and {h2}")
        return
    
    print(f"  🏓 Testing ping: {h1}({ip1}) -> {h2}({ip2})")
    stdout, stderr, rc = run_cmd(f"ip netns exec {h1} ping -c 3 -W 2 {ip2}")
    
    if rc == 0 and "3 received" in stdout:
        print("    ✅ Ping successful!")
    else:
        print("    ❌ Ping failed")
        print(f"    📝 Output: {stdout}")

def show_switch_status():
    """Show current switch status"""
    print("📊 Switch Status:")
    switches = get_ovs_switches()
    
    for switch in switches:
        print(f"\n🔍 {switch}:")
        
        # Show ports
        stdout, _, _ = run_cmd(f"ovs-ofctl show {switch}")
        port_count = len([l for l in stdout.split('\n') if 'addr:' in l])
        print(f"  📡 Ports: {port_count}")
        
        # Show flows
        stdout, _, _ = run_cmd(f"ovs-ofctl dump-flows {switch}")
        flow_count = len([l for l in stdout.split('\n') if 'actions=' in l])
        print(f"  📋 Flows: {flow_count}")
        
        # Show controller
        stdout, _, _ = run_cmd(f"ovs-vsctl get-controller {switch}")
        controller = stdout.strip()
        print(f"  🎮 Controller: {controller}")

def main():
    """Main function with menu"""
    if len(sys.argv) > 1:
        action = sys.argv[1]
    else:
        print("\n🛠️ Mininet Connectivity Fix Utility")
        print("=" * 50)
        print("1. Quick Fix (recommended)")
        print("2. Full Reset")
        print("3. Emergency Learning Switch")
        print("4. Test Connectivity")
        print("5. Show Status")
        print("6. Manual Options")
        print("=" * 50)
        
        choice = input("Select option (1-6): ").strip()
        
        if choice == "1":
            action = "quick"
        elif choice == "2":
            action = "full"
        elif choice == "3":
            action = "emergency"
        elif choice == "4":
            action = "test"
        elif choice == "5":
            action = "status"
        elif choice == "6":
            action = "manual"
        else:
            print("Invalid choice")
            return
    
    print(f"\n🚀 Running action: {action}")
    print("=" * 50)
    
    if action == "quick":
        # Quick fix - most common issues
        flush_ovs_flows()
        clear_host_arp()
        install_basic_flows()
        time.sleep(2)
        test_connectivity()
        
    elif action == "full":
        # Full reset
        flush_ovs_flows()
        flush_bridge_tables()
        clear_host_arp()
        restart_interfaces()
        reset_fail_mode()
        install_basic_flows()
        time.sleep(3)
        test_connectivity()
        
    elif action == "emergency":
        # Emergency learning switch mode
        emergency_learning_switch()
        clear_host_arp()
        time.sleep(2)
        test_connectivity()
        
    elif action == "test":
        # Just test connectivity
        test_connectivity()
        
    elif action == "status":
        # Show status
        show_switch_status()
        
    elif action == "manual":
        print("\n🔧 Manual Options:")
        print("  python fix_connectivity.py flush_flows")
        print("  python fix_connectivity.py flush_arp")
        print("  python fix_connectivity.py reset_mode")
        print("  python fix_connectivity.py basic_flows")
        print("  python fix_connectivity.py restart_interfaces")
        
    elif action == "flush_flows":
        flush_ovs_flows()
    elif action == "flush_arp":
        clear_host_arp()
    elif action == "reset_mode":
        reset_fail_mode()
    elif action == "basic_flows":
        install_basic_flows()
    elif action == "restart_interfaces":
        restart_interfaces()
    else:
        print(f"Unknown action: {action}")
        return
    
    print("\n✅ Action completed!")

if __name__ == "__main__":
    main()
