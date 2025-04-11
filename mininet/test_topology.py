from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import os


class TestTopology(Topo):
    def build(self):
        # Add switches
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')
        
        # Add hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        h5 = self.addHost('h5', ip='10.0.0.5/24')
        h6 = self.addHost('h6', ip='10.0.0.6/24')
        
        # Host-to-switch links
        self.addLink(h1, s1, cls=TCLink, bw=10)
        self.addLink(h2, s1, cls=TCLink, bw=10)
        self.addLink(h3, s2, cls=TCLink, bw=10)
        self.addLink(h4, s2, cls=TCLink, bw=10)
        self.addLink(h5, s3, cls=TCLink, bw=10)
        self.addLink(h6, s3, cls=TCLink, bw=10)
        
        # Switch-to-switch links
        self.addLink(s1, s2, cls=TCLink, bw=20)
        self.addLink(s2, s3, cls=TCLink, bw=20)


def start_packet_capture(net, duration=60):
    pcap_dir = "/tmp/pcap_files"
    os.makedirs(pcap_dir, exist_ok=True)

    info("[INFO] Starting tcpdump packet capture on all hosts...\n")

    for host in net.hosts:
        pcap_file = os.path.join(pcap_dir, f"{host.name}.pcap")
        host.cmd(f"tcpdump -i {host.name}-eth0 -w {pcap_file} &")
    
    # Optional: wait duration or just let it capture during testing
    # time.sleep(duration)
    # host.cmd("pkill tcpdump")  # Or manually kill later

def simulate_anomalous_traffic(net):
    info("\n[INFO] Simulating normal and anomalous traffic...\n")
    h1, h3, h5, h2, h4, h6 = net.get('h1', 'h3', 'h5', 'h2', 'h4', 'h6')

    # Normal Traffic
    info("[INFO] Starting normal traffic (iperf between h1 and h3)...\n")
    h1.cmd('iperf -s &')
    h3.cmd(f'iperf -c {h1.IP()} -t 20 &')

    time.sleep(20)

    # Simulated DDoS Attack
    info("[ALERT] Simulating DDoS attack from h2, h4, and h6 to h1...\n")
    attack_pids = []

    for attacker in [h2, h4, h6]:
        pid_cmd = f'echo $$; hping3 -i u1000 -S -p 80 {h1.IP()} > /dev/null 2>&1 & echo $!'
        time.sleep(0.5)  # small delay between launching each attack
        result = attacker.cmd(pid_cmd).strip()

        try:
            pid = int(result.splitlines()[-1])  # Get the last line (PID)
            attack_pids.append((attacker, pid))
            info(f"[INFO] Started attack from {attacker.name}, PID: {pid}\n")
        except Exception as e:
            info(f"[ERROR] Could not get PID from attacker {attacker.name}: {e}\n")
            continue

    # Let attacks run for 10 seconds
    time.sleep(10)

    # Stop all attack processes
    for attacker, pid in attack_pids:
        attacker.cmd(f'kill {pid}')
        info(f"[INFO] Killed attack process from {attacker.name} (PID: {pid})\n")



def start_network():
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
    
    for switch in net.switches:
        info(f"[INFO] Configuring {switch.name} for OpenFlow 1.3\n")
        switch.cmd('ovs-vsctl set bridge', switch.name, 'protocols=OpenFlow13')

    for switch in net.switches:
        info(f"[INFO] Clearing flows on {switch.name}\n")
        switch.cmd('ovs-ofctl del-flows', switch.name)

    start_packet_capture(net)
    info("\n[INFO] Testing network connectivity...\n")
    net.pingAll()

    simulate_anomalous_traffic(net)

    info("\n[INFO] Network is now ready for manual testing. Entering CLI...\n")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    start_network()
