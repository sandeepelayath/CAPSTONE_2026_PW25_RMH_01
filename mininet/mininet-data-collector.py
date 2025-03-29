from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import json
import pandas as pd
import os
import datetime
import re

class DataCollectorTopo(Topo):
    def build(self):
        # Add switches
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        
        # Add hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        
        # Add links with bandwidth and delay specifications
        self.addLink(h1, s1, cls=TCLink, bw=10)
        self.addLink(h2, s1, cls=TCLink, bw=10)
        self.addLink(h3, s2, cls=TCLink, bw=10)
        self.addLink(h4, s2, cls=TCLink, bw=10)
        self.addLink(s1, s2, cls=TCLink, bw=20)

def collect_flow_stats(net, interval=5, duration=60):
    """
    Collects flow statistics from switches at regular intervals
    """
    info("\n[INFO] Starting flow statistics collection...\n")
    flow_data = []
    start_time = time.time()
    end_time = start_time + duration
    
    while time.time() < end_time:
        current_time = time.time()
        time_str = datetime.datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')
        
        for switch in net.switches:
            flow_stats_str = switch.cmd('ovs-ofctl -O OpenFlow13 dump-flows', switch.name)
            flows = flow_stats_str.strip().split('\n')[1:]  # Skip header
            
            for flow in flows:
                if 'NXST' in flow:
                    continue
                
                flow_dict = parse_flow_entry(flow)
                flow_dict['switch'] = switch.name
                flow_dict['timestamp'] = time_str
                flow_dict['collection_time'] = current_time
                
                is_anomaly = detect_anomaly(flow_dict)
                flow_dict['label'] = 'ATTACK' if is_anomaly else 'BENIGN'
                
                flow_data.append(flow_dict)
        
        info(f"[INFO] Collected {len(flow_data)} flow entries so far\n")
        time.sleep(interval)
    
    df = pd.DataFrame(flow_data)
    
    # Rename features to match CIC-IDS2017
    rename_map = {
        "duration_sec": "Flow Duration",
        "packet_count": "Total Fwd Packets",
        "byte_count": "Total Length of Fwd Packets",
        "bytes_per_sec": "Flow Bytes/s",
        "packets_per_sec": "Flow Packets/s",
        "avg_packet_size": "Average Packet Size",
        "tcp_flag_count": "Flow TCP Flags",
        "src_port": "Source Port",
        "dst_port": "Destination Port",
        "protocol": "Protocol"
    }
    df.rename(columns=rename_map, inplace=True)
    
    output_file = f'mininet_flow_data_{int(start_time)}.csv'
    df.to_csv(output_file, index=False)
    info(f"\n[INFO] Saved flow data to {output_file}\n")
    return df

def parse_flow_entry(flow_entry):
    """Parse a single flow entry from ovs-ofctl output."""
    parts = flow_entry.split(',')
    flow_dict = {}
    for part in parts:
        part = part.strip()
        if 'cookie=' in part:
            flow_dict['cookie'] = part.split('=')[1]
        elif 'duration=' in part:
            duration_parts = part.split('=')[1].split('s')
            flow_dict['duration_sec'] = float(duration_parts[0])
        elif 'n_packets=' in part:
            flow_dict['packet_count'] = int(part.split('=')[1])
        elif 'n_bytes=' in part:
            flow_dict['byte_count'] = int(part.split('=')[1])
        elif 'priority=' in part:
            match = re.search(r'priority=(\d+)', part)
            flow_dict['priority'] = int(match.group(1)) if match else 0

    if 'duration_sec' in flow_dict and flow_dict['duration_sec'] > 0:
        if 'byte_count' in flow_dict:
            flow_dict['bytes_per_sec'] = flow_dict['byte_count'] / max(flow_dict['duration_sec'], 0.001)
        if 'packet_count' in flow_dict:
            flow_dict['packets_per_sec'] = flow_dict['packet_count'] / max(flow_dict['duration_sec'], 0.001)

    if 'packet_count' in flow_dict and flow_dict['packet_count'] > 0:
        flow_dict['avg_packet_size'] = flow_dict['byte_count'] / flow_dict['packet_count']
    
    return flow_dict

def detect_anomaly(flow_dict):
    """Basic heuristic for anomaly detection."""
    if flow_dict.get('packets_per_sec', 0) > 1000:
        return True
    if flow_dict.get('avg_packet_size', 0) < 60 and flow_dict.get('packet_count', 0) > 10:
        return True
    return False

def start_data_collection():
    topo = DataCollectorTopo()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        switch=OVSKernelSwitch,
        autoSetMacs=True
    )
    
    net.start()
    info("\n[INFO] Testing network connectivity...\n")
    net.pingAll()
    
    flow_data = collect_flow_stats(net, interval=5, duration=60)
    CLI(net)
    net.stop()
    return flow_data

if __name__ == '__main__':
    setLogLevel('info')
    start_data_collection()
