from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import psutil
import json
from datetime import datetime
import os
import threading

class TestTopology(Topo):
    def build(self):
        # Add switches
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')  # Added third switch for more complex topology
        
        # Add hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')  # Server
        h2 = self.addHost('h2', ip='10.0.0.2/24')  # Normal Client
        h3 = self.addHost('h3', ip='10.0.0.3/24')  # Attacker 1
        h4 = self.addHost('h4', ip='10.0.0.4/24')  # Attacker 2
        h5 = self.addHost('h5', ip='10.0.0.5/24')  # Normal Client
        h6 = self.addHost('h6', ip='10.0.0.6/24')  # Monitoring Host
        
        # Add links with bandwidth and delay specifications
        self.addLink(h1, s1, cls=TCLink, bw=100, delay='2ms')  # Server link
        self.addLink(h2, s1, cls=TCLink, bw=10, delay='5ms')
        self.addLink(h3, s2, cls=TCLink, bw=10, delay='5ms')
        self.addLink(h4, s2, cls=TCLink, bw=10, delay='5ms')
        self.addLink(h5, s3, cls=TCLink, bw=10, delay='5ms')
        self.addLink(h6, s3, cls=TCLink, bw=100, delay='2ms')  # Monitoring link
        self.addLink(s1, s2, cls=TCLink, bw=50, delay='10ms')
        self.addLink(s2, s3, cls=TCLink, bw=50, delay='10ms')
        self.addLink(s1, s3, cls=TCLink, bw=50, delay='10ms')

class NetworkTester:
    def __init__(self, net):
        self.net = net
        self.test_scenarios = {
            'normal_traffic': self.generate_normal_traffic,
            'ddos_attack': self.generate_ddos_attack,
            'port_scan': self.generate_port_scan,
            'slowloris': self.generate_slowloris_attack,
            'sql_injection': self.generate_sql_injection
        }
        self.metrics = {
            'start_time': None,
            'end_time': None,
            'scenarios': {},
            'system_metrics': []
        }
        self.log_dir = 'test_logs'
        os.makedirs(self.log_dir, exist_ok=True)

    def _collect_system_metrics(self):
        """Collects system-wide performance metrics"""
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'network_io': psutil.net_io_counters()._asdict()
        }
        self.metrics['system_metrics'].append(metrics)

    def generate_normal_traffic(self, duration=30):
        """Generates normal network traffic patterns"""
        info("\n[INFO] Generating normal traffic...\n")
        h1, h2, h5 = self.net.get('h1', 'h2', 'h5')
        
        # HTTP traffic
        h1.cmd('python -m SimpleHTTPServer 80 &')
        h2.cmd('for i in {1..50}; do wget -q -O /dev/null http://10.0.0.1:80; sleep 0.2; done &')
        h5.cmd('for i in {1..50}; do wget -q -O /dev/null http://10.0.0.1:80; sleep 0.3; done &')
        
        # ICMP traffic
        h2.cmd('ping 10.0.0.1 -c 10 -i 0.2 &')
        h5.cmd('ping 10.0.0.1 -c 10 -i 0.3 &')
        
        # TCP traffic
        h1.cmd('iperf -s -p 5001 &')
        h2.cmd('iperf -c 10.0.0.1 -p 5001 -t 20 -i 1 &')
        h5.cmd('iperf -c 10.0.0.1 -p 5001 -t 20 -i 1 &')
        
        time.sleep(duration)

    def generate_ddos_attack(self, duration=30):
        """Simulates a DDoS attack"""
        info("\n[ALERT] Simulating DDoS attack...\n")
        h3, h4 = self.net.get('h3', 'h4')
        
        # SYN Flood
        h3.cmd('hping3 -S -p 80 --flood 10.0.0.1 &')
        # UDP Flood
        h4.cmd('hping3 --udp -p 53 --flood 10.0.0.1 &')
        
        time.sleep(duration)
        
        # Cleanup
        h3.cmd('killall hping3')
        h4.cmd('killall hping3')

    def generate_port_scan(self, duration=30):
        """Simulates a port scanning attack"""
        info("\n[ALERT] Simulating port scan...\n")
        h3 = self.net.get('h3')
        
        # TCP SYN scan
        h3.cmd('nmap -sS -T4 10.0.0.1 &')
        # UDP scan
        h3.cmd('nmap -sU -T4 --top-ports 100 10.0.0.1 &')
        
        time.sleep(duration)
        
        # Cleanup
        h3.cmd('killall nmap')

    def generate_slowloris_attack(self, duration=30):
        """Simulates a Slowloris DoS attack"""
        info("\n[ALERT] Simulating Slowloris attack...\n")
        h4 = self.net.get('h4')
        
        # Start Apache on target
        h1 = self.net.get('h1')
        h1.cmd('apache2 -k start')
        
        # Launch Slowloris attack
        h4.cmd('python3 slowloris.py 10.0.0.1 --port 80 --sockets 1000 &')
        
        time.sleep(duration)
        
        # Cleanup
        h4.cmd('killall python3')
        h1.cmd('apache2 -k stop')

    def generate_sql_injection(self, duration=30):
        """Simulates SQL injection attempts"""
        info("\n[ALERT] Simulating SQL injection...\n")
        h3 = self.net.get('h3')
        
        # Simulate SQL injection attempts
        injection_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users; --"
        ]
        
        for payload in injection_payloads:
            h3.cmd(f'curl "http://10.0.0.1/login.php?username=admin&password={payload}" &')
            time.sleep(1)
        
        time.sleep(duration)

    def run_test_scenario(self, scenario_name, duration=30):
        """Runs a specific test scenario and collects metrics"""
        if scenario_name not in self.test_scenarios:
            info(f"\n[ERROR] Unknown test scenario: {scenario_name}\n")
            return
        
        info(f"\n[INFO] Running test scenario: {scenario_name}\n")
        
        # Initialize scenario metrics
        self.metrics['scenarios'][scenario_name] = {
            'start_time': datetime.now().isoformat(),
            'duration': duration
        }
        
        # Start metric collection
        metric_collection_thread = threading.Thread(
            target=lambda: [self._collect_system_metrics() for _ in range(duration)]
        )
        metric_collection_thread.start()
        
        # Run the scenario
        self.test_scenarios[scenario_name](duration)
        
        # Wait for metric collection to complete
        metric_collection_thread.join()
        
        # Record end time
        self.metrics['scenarios'][scenario_name]['end_time'] = datetime.now().isoformat()
        
        self._save_metrics()

    def _save_metrics(self):
        """Saves collected metrics to a JSON file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(self.log_dir, f'test_metrics_{timestamp}.json')
        
        with open(filename, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        
        info(f"\n[INFO] Metrics saved to {filename}\n")

    def cleanup(self):
        """Cleans up all running processes and temporary files"""
        info("\n[INFO] Cleaning up test environment...\n")
        
        cleanup_commands = [
            'killall hping3',
            'killall nmap',
            'killall python3',
            'killall iperf',
            'killall apache2',
            'rm -f /tmp/test_*'
        ]
        
        for host in self.net.hosts:
            for cmd in cleanup_commands:
                host.cmd(cmd)

def start_network():
    """Starts the Mininet network and runs test scenarios"""
    topo = TestTopology()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        switch=OVSKernelSwitch,
        autoSetMacs=True
    )
    
    net.start()
    
    info("\n[INFO] Waiting for switches to connect to the Ryu controller...\n")
    time.sleep(5)
    
    # Configure OpenFlow 1.3
    for switch in net.switches:
        info(f"[INFO] Configuring {switch.name} for OpenFlow 1.3\n")
        switch.cmd('ovs-vsctl set bridge', switch.name, 'protocols=OpenFlow13')

    # Clear all flows
    for switch in net.switches:
        info(f"[INFO] Clearing flows on {switch.name}\n")
        switch.cmd('ovs-ofctl del-flows', switch.name)
    
    # Test network connectivity
    info("\n[INFO] Testing network connectivity...\n")
    net.pingAll()
    
    # Initialize and run tests
    tester = NetworkTester(net)
    
    # Run test scenarios
    test_scenarios = [
        ('normal_traffic', 30),
        ('ddos_attack', 30),
        ('port_scan', 30),
        ('slowloris', 30),
        ('sql_injection', 30)
    ]
    
    for scenario, duration in test_scenarios:
        tester.run_test_scenario(scenario, duration)
    
    # Cleanup
    tester.cleanup()
    
    info("\n[INFO] All test scenarios completed. Entering CLI for manual testing...\n")
    CLI(net)
    
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    start_network()
