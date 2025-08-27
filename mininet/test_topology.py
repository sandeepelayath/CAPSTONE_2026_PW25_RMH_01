from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import os
import json
from datetime import datetime


class EnhancedTestTopology(Topo):
    def build(self):
        # Add switches with OpenFlow 1.3 support for meter rules
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')
        
        # Add hosts with specific roles for testing
        # Legitimate traffic sources
        h1 = self.addHost('h1', ip='10.0.0.1/24')  # Normal user
        h2 = self.addHost('h2', ip='10.0.0.2/24')  # Web server
        
        # Test sources for different risk levels
        h3 = self.addHost('h3', ip='10.0.0.3/24')  # Low risk tester
        h4 = self.addHost('h4', ip='10.0.0.4/24')  # Medium risk tester
        h5 = self.addHost('h5', ip='10.0.0.5/24')  # High risk tester
        h6 = self.addHost('h6', ip='10.0.0.6/24')  # Multi-stage attacker
        
        # Additional hosts for advanced testing
        h7 = self.addHost('h7', ip='10.0.0.7/24')  # Whitelist candidate
        h8 = self.addHost('h8', ip='10.0.0.8/24')  # Blacklist candidate
        
        # Host-to-switch links with traffic control
        self.addLink(h1, s1, cls=TCLink, bw=10)
        self.addLink(h2, s1, cls=TCLink, bw=10)
        self.addLink(h3, s2, cls=TCLink, bw=10)
        self.addLink(h4, s2, cls=TCLink, bw=10)
        self.addLink(h5, s3, cls=TCLink, bw=10)
        self.addLink(h6, s3, cls=TCLink, bw=10)
        self.addLink(h7, s1, cls=TCLink, bw=10)
        self.addLink(h8, s2, cls=TCLink, bw=10)
        
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

def test_risk_based_mitigations(net):
    """Comprehensive test suite for all risk-based mitigation logics"""
    info("\n" + "="*80)
    info("🧪 STARTING COMPREHENSIVE RISK-BASED MITIGATION TESTS")
    info("="*80 + "\n")
    
    h1, h2, h3, h4, h5, h6, h7, h8 = net.get('h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'h8')
    
    # Setup services on target hosts
    setup_test_services(net)
    
    # Wait for network to stabilize and let initial connectivity be established
    info("⏳ Allowing network to stabilize and establish normal baseline traffic...\n")
    time.sleep(15)
    
    # Test 1: Establish normal baseline traffic first (very low risk)
    test_baseline_traffic(h1, h2, h7)
    
    # Test 2: Low Risk Traffic (Should be allowed and potentially whitelisted)
    test_low_risk_traffic(h7, h1, h2)
    
    # Test 3: Medium Risk Traffic (Should trigger rate limiting)
    test_medium_risk_traffic(h4, h1, h2)
    
    # Test 4: High Risk Traffic (Should trigger short timeout + blacklisting)
    test_high_risk_traffic(h5, h1, h2)
    
    # Test 5: Escalating Risk Pattern (Test blacklist escalation)
    test_escalating_risk_pattern(h6, h1, h2)
    
    # Test 6: Whitelist Recovery Test (Test false positive handling)
    test_whitelist_recovery(h3, h1, h2)
    
    # Test 7: Mixed Traffic Analysis (Real-world scenario)
    test_mixed_traffic_scenario(net)
    
    # Test 8: Rate Limiting Effectiveness
    test_rate_limiting_effectiveness(h4, h1)
    
    # Test 9: Blacklist Learning and Decay
    test_blacklist_learning(h8, h1, h2)
    
    # Allow time for mitigation system to process
    info("\n⏱️ Allowing mitigation system to process and adapt...\n")
    time.sleep(30)
    
    # Display final test results
    display_test_results()

def test_baseline_traffic(source1, source2, target):
    """Test Case 0: Establish normal baseline traffic to calibrate the system"""
    info("\n" + "="*60)
    info("🟦 TEST 0: BASELINE TRAFFIC ESTABLISHMENT")
    info("="*60)
    info(f"📋 Expected: Establish normal traffic patterns")
    info(f"🎯 Sources: {source1.name}, {source2.name}")
    info(f"🎯 Target: {target.name}\n")
    
    info("🔄 Generating normal baseline traffic patterns...\n")
    
    # Very simple, low-frequency legitimate traffic
    for i in range(10):
        # Simple ping between hosts
        source1.cmd(f'ping -c 1 {target.IP()} > /dev/null 2>&1')
        time.sleep(5)  # Very slow, clearly legitimate
        
        if i % 3 == 0:
            source2.cmd(f'ping -c 1 {source1.IP()} > /dev/null 2>&1')
            time.sleep(3)
    
    info("✅ Baseline traffic established")
    info("💡 This should establish normal traffic patterns with very low risk scores\n")
    time.sleep(10)

def setup_test_services(net):
    """Setup various services for testing different attack vectors"""
    info("🔧 Setting up test services...\n")
    
    h1, h2 = net.get('h1', 'h2')
    
    # Web servers for different types of attacks
    h1.cmd('python3 -m http.server 8080 > /dev/null 2>&1 &')  # HTTP server
    h2.cmd('python3 -m http.server 8081 > /dev/null 2>&1 &')  # HTTP server
    h1.cmd('nc -l -p 2222 > /dev/null 2>&1 &')                # SSH-like service
    h2.cmd('nc -l -p 3306 > /dev/null 2>&1 &')                # MySQL-like service
    h1.cmd('nc -l -p 1433 > /dev/null 2>&1 &')                # SQL Server-like service
    
    time.sleep(2)
    info("✅ Test services are ready\n")

def test_low_risk_traffic(source, target1, target2):
    """Test Case 1: Generate low-risk traffic that should be allowed"""
    info("\n" + "="*60)
    info("🟢 TEST 1: LOW RISK TRAFFIC (Risk Score < 0.1)")
    info("="*60)
    info(f"📋 Expected: Allow traffic, monitor for whitelisting")
    info(f"🎯 Source: {source.name} ({source.IP()})")
    info(f"🎯 Targets: {target1.name}, {target2.name}\n")
    
    info("🔄 Generating consistent low-risk patterns...\n")
    
    # Generate normal HTTP requests (low frequency, normal patterns)
    for i in range(15):
        source.cmd(f'curl -s http://{target1.IP()}:8080/ > /dev/null 2>&1')
        time.sleep(2)  # Slow, normal requests
        if i % 5 == 0:
            source.cmd(f'curl -s http://{target2.IP()}:8081/ > /dev/null 2>&1')
            time.sleep(1)
    
    info("✅ Low-risk traffic pattern completed")
    info("💡 This should trigger whitelisting after 10 consecutive low-risk flows\n")
    time.sleep(5)

def test_medium_risk_traffic(source, target1, target2):
    """Test Case 2: Generate medium-risk traffic for rate limiting"""
    info("\n" + "="*60)
    info("🟡 TEST 2: MEDIUM RISK TRAFFIC (Risk Score 0.1-0.4)")
    info("="*60)
    info(f"📋 Expected: Rate limiting with OpenFlow meters")
    info(f"🎯 Source: {source.name} ({source.IP()})")
    info(f"🎯 Targets: {target1.name}, {target2.name}\n")
    
    info("🔄 Generating medium-risk patterns...\n")
    
    # Moderate port scanning (should trigger medium risk)
    info("🔍 Performing moderate port scan...\n")
    source.cmd(f'nmap -sS -p 80,443,8080,22,21 {target1.IP()} > /dev/null 2>&1')
    time.sleep(3)
    
    # Moderate frequency HTTP requests
    info("🌐 Generating moderate frequency HTTP requests...\n")
    for i in range(20):
        source.cmd(f'curl -s http://{target1.IP()}:8080/ > /dev/null 2>&1')
        time.sleep(0.5)  # Faster than normal but not extreme
    
    # Some suspicious but not malicious SQL queries
    info("🗃️ Testing with mildly suspicious database queries...\n")
    suspicious_queries = [
        "SELECT * FROM users",
        "SELECT * FROM products WHERE id=1",
        "SELECT * FROM admin_users"
    ]
    
    for query in suspicious_queries:
        encoded_query = query.replace(" ", "%20")
        source.cmd(f'curl -s "http://{target2.IP()}:8081/search?q={encoded_query}" > /dev/null 2>&1')
        time.sleep(1)
    
    info("✅ Medium-risk traffic pattern completed")
    info("💡 This should trigger rate limiting (80%, 50%, or 20% based on exact risk score)\n")
    time.sleep(5)

def test_high_risk_traffic(source, target1, target2):
    """Test Case 3: Generate high-risk traffic for blocking + blacklisting"""
    info("\n" + "="*60)
    info("🔴 TEST 3: HIGH RISK TRAFFIC (Risk Score ≥ 0.4)")
    info("="*60)
    info(f"📋 Expected: Short timeout blocking + blacklisting")
    info(f"🎯 Source: {source.name} ({source.IP()})")
    info(f"🎯 Targets: {target1.name}, {target2.name}\n")
    
    info("🔄 Generating high-risk attack patterns...\n")
    
    # SQL Injection attack (high risk)
    info("💉 Performing SQL injection attack...\n")
    sql_payloads = [
        "' OR '1'='1' --",
        "'; DROP TABLE users; --",
        "' UNION SELECT password FROM users --",
        "admin'/*",
        "1' AND 1=1 --"
    ]
    
    for payload in sql_payloads:
        encoded_payload = payload.replace("'", "%27").replace(" ", "%20").replace(";", "%3B")
        source.cmd(f'curl -s "http://{target1.IP()}:8080/login?user={encoded_payload}" > /dev/null 2>&1')
        time.sleep(0.5)
    
    # Aggressive port scanning
    info("🔍 Performing aggressive port scan...\n")
    source.cmd(f'nmap -sS -T4 -p 1-1000 {target1.IP()} > /dev/null 2>&1 &')
    time.sleep(5)
    source.cmd('pkill nmap')
    
    # DDoS-like traffic
    info("💥 Generating DDoS-like traffic...\n")
    for i in range(50):
        source.cmd(f'curl -s http://{target2.IP()}:8081/ > /dev/null 2>&1 &')
        if i % 10 == 0:
            time.sleep(0.1)
    
    # Brute force attempt
    info("🔨 Performing brute force attack...\n")
    passwords = ['admin', 'password', '123456', 'root', 'qwerty']
    for pwd in passwords:
        source.cmd(f'timeout 2 nc {target1.IP()} 2222 < /dev/null > /dev/null 2>&1')
        time.sleep(0.2)
    
    info("✅ High-risk traffic pattern completed")
    info("💡 This should trigger immediate blocking and blacklisting\n")
    time.sleep(5)

def test_escalating_risk_pattern(source, target1, target2):
    """Test Case 4: Test blacklist escalation with repeated offenses"""
    info("\n" + "="*60)
    info("📈 TEST 4: ESCALATING RISK PATTERN (Blacklist Learning)")
    info("="*60)
    info(f"📋 Expected: Increasing timeout durations for repeat offenses")
    info(f"🎯 Source: {source.name} ({source.IP()})")
    info(f"🎯 Targets: {target1.name}, {target2.name}\n")
    
    for round_num in range(3):
        info(f"🔄 Escalation Round {round_num + 1}/3...\n")
        
        # Generate high-risk traffic multiple times
        source.cmd(f'nmap -sS -T5 -p 1-500 {target1.IP()} > /dev/null 2>&1')
        time.sleep(2)
        
        # SQL injection
        source.cmd(f'curl -s "http://{target2.IP()}:8081/admin?cmd=DROP%20TABLE%20users" > /dev/null 2>&1')
        time.sleep(1)
        
        # Wait for mitigation system to process
        time.sleep(10)
        
        info(f"✅ Round {round_num + 1} completed - timeout should be {2**(round_num+1)} times longer\n")
    
    info("💡 Each round should result in exponentially longer blacklist timeouts\n")

def test_whitelist_recovery(source, target1, target2):
    """Test Case 5: Test false positive recovery through whitelisting"""
    info("\n" + "="*60)
    info("⚪ TEST 5: WHITELIST RECOVERY (False Positive Handling)")
    info("="*60)
    info(f"📋 Expected: Recovery from false positive through good behavior")
    info(f"🎯 Source: {source.name} ({source.IP()})")
    info(f"🎯 Targets: {target1.name}, {target2.name}\n")
    
    # First, generate some suspicious traffic (might be false positive)
    info("🔄 Generating potentially suspicious traffic...\n")
    source.cmd(f'nmap -sS -p 80,443 {target1.IP()} > /dev/null 2>&1')
    time.sleep(3)
    
    # Then, generate consistent legitimate traffic for recovery
    info("🔄 Now generating consistent legitimate traffic for recovery...\n")
    for i in range(20):
        source.cmd(f'curl -s http://{target1.IP()}:8080/ > /dev/null 2>&1')
        time.sleep(3)  # Very slow, legitimate requests
        
        if i % 5 == 0:
            info(f"   📊 Legitimate request {i+1}/20 sent")
    
    info("✅ Recovery pattern completed")
    info("💡 This should demonstrate false positive recovery and potential whitelisting\n")
    time.sleep(5)

def test_mixed_traffic_scenario(net):
    """Test Case 6: Real-world mixed traffic scenario"""
    info("\n" + "="*60)
    info("🌍 TEST 6: MIXED TRAFFIC SCENARIO (Real-world Simulation)")
    info("="*60)
    info(f"📋 Expected: Different mitigations for different sources simultaneously\n")
    
    h1, h2, h3, h4, h5, h6, h7, h8 = net.get('h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'h8')
    
    info("🔄 Starting mixed traffic simulation...\n")
    
    # Legitimate traffic from h1 and h7
    info("✅ Starting legitimate background traffic...\n")
    h1.cmd(f'while true; do curl -s http://{h2.IP()}:8081/ > /dev/null 2>&1; sleep 5; done &')
    h7.cmd(f'while true; do curl -s http://{h2.IP()}:8081/ > /dev/null 2>&1; sleep 7; done &')
    
    # Medium risk from h3
    info("🟡 Starting medium-risk traffic pattern...\n")
    h3.cmd(f'while true; do curl -s http://{h2.IP()}:8081/ > /dev/null 2>&1; sleep 1; done &')
    
    # High risk from h5
    info("🔴 Starting high-risk attack pattern...\n")
    h5.cmd(f'hping3 -i u1000 -S -p 80 {h2.IP()} > /dev/null 2>&1 &')
    
    # Let traffic run
    time.sleep(20)
    
    # Stop background traffic
    for host in [h1, h3, h5, h7]:
        host.cmd('pkill -f curl')
        host.cmd('pkill hping3')
    
    info("✅ Mixed traffic scenario completed")
    info("💡 This tests the system's ability to handle multiple risk levels simultaneously\n")

def test_rate_limiting_effectiveness(source, target):
    """Test Case 7: Verify rate limiting effectiveness"""
    info("\n" + "="*60)
    info("📊 TEST 7: RATE LIMITING EFFECTIVENESS")
    info("="*60)
    info(f"📋 Expected: Measurable reduction in traffic throughput")
    info(f"🎯 Source: {source.name} ({source.IP()})")
    info(f"🎯 Target: {target.name} ({target.IP()})\n")
    
    # First, establish baseline traffic rate
    info("📏 Measuring baseline traffic rate...\n")
    start_time = time.time()
    baseline_count = 0
    
    for i in range(50):
        source.cmd(f'curl -s http://{target.IP()}:8080/ > /dev/null 2>&1')
        baseline_count += 1
    
    baseline_time = time.time() - start_time
    baseline_rate = baseline_count / baseline_time
    
    info(f"📊 Baseline rate: {baseline_rate:.2f} requests/second\n")
    
    # Generate traffic that should trigger rate limiting
    info("🔄 Generating traffic to trigger rate limiting...\n")
    source.cmd(f'nmap -sS -p 1-100 {target.IP()} > /dev/null 2>&1')
    time.sleep(5)  # Wait for rate limiting to be applied
    
    # Measure rate-limited traffic
    info("📏 Measuring rate-limited traffic rate...\n")
    start_time = time.time()
    limited_count = 0
    
    for i in range(50):
        source.cmd(f'curl -s http://{target.IP()}:8080/ > /dev/null 2>&1')
        limited_count += 1
    
    limited_time = time.time() - start_time
    limited_rate = limited_count / limited_time
    
    info(f"📊 Rate-limited rate: {limited_rate:.2f} requests/second")
    
    if limited_rate < baseline_rate * 0.8:  # Should be significantly slower
        info("✅ Rate limiting is effective!")
    else:
        info("⚠️ Rate limiting may not be working as expected")
    
    info("💡 Rate limiting should show measurable traffic reduction\n")

def test_blacklist_learning(source, target1, target2):
    """Test Case 8: Test blacklist learning and timeout escalation"""
    info("\n" + "="*60)
    info("⚫ TEST 8: BLACKLIST LEARNING AND TIMEOUT ESCALATION")
    info("="*60)
    info(f"📋 Expected: Progressive timeout increases for repeat offenders")
    info(f"🎯 Source: {source.name} ({source.IP()})")
    info(f"🎯 Targets: {target1.name}, {target2.name}\n")
    
    for attempt in range(3):
        info(f"🔄 Blacklist attempt {attempt + 1}/3...\n")
        
        # Generate consistent high-risk behavior
        source.cmd(f'curl -s "http://{target1.IP()}:8080/admin?cmd=DROP%20DATABASE" > /dev/null 2>&1')
        source.cmd(f'nmap -sS -T5 -p 1-200 {target2.IP()} > /dev/null 2>&1')
        
        # Record attempt time
        attempt_time = datetime.now().isoformat()
        info(f"   📝 Attempt logged at {attempt_time}")
        
        # Wait for mitigation processing
        time.sleep(15)
        
        expected_timeout = 60 * (2 ** attempt)  # Exponential increase
        info(f"   ⏱️ Expected timeout for this attempt: {expected_timeout} seconds\n")
    
    info("✅ Blacklist learning test completed")
    info("💡 Each successive violation should result in longer blacklist periods\n")

def display_test_results():
    """Display comprehensive test results and system status"""
    info("\n" + "="*80)
    info("📈 COMPREHENSIVE TEST RESULTS SUMMARY")
    info("="*80 + "\n")
    
    # Check if risk mitigation log exists
    log_files = [
        'controller/risk_mitigation_actions.json',
        'controller/mitigation_actions.json'
    ]
    
    actions = []
    for log_file in log_files:
        try:
            with open(log_file, 'r') as f:
                file_actions = [json.loads(line) for line in f if line.strip()]
                actions.extend(file_actions)
            break
        except FileNotFoundError:
            continue
    
    if actions:
        info("📊 MITIGATION STATISTICS:")
        
        # Count different action types
        allow_count = len([a for a in actions if a.get('action_type') == 'ALLOW'])
        rate_limit_count = len([a for a in actions if a.get('action_type') == 'RATE_LIMIT'])
        block_count = len([a for a in actions if a.get('action_type') in ['SHORT_TIMEOUT_BLOCK', 'BLOCK']])
        
        info(f"  ✅ Allowed: {allow_count}")
        info(f"  ⚠️ Rate Limited: {rate_limit_count}")
        info(f"  🚫 Blocked: {block_count}")
        info(f"  📝 Total Actions: {len(actions)}")
        
        # Risk score analysis
        risk_scores = [float(a.get('risk_score', 0)) for a in actions if 'risk_score' in a]
        if risk_scores:
            info(f"\n📊 RISK SCORE ANALYSIS:")
            info(f"  📈 Average Risk Score: {sum(risk_scores)/len(risk_scores):.3f}")
            info(f"  📊 Maximum Risk Score: {max(risk_scores):.3f}")
            info(f"  📉 Minimum Risk Score: {min(risk_scores):.3f}")
        
        # Source analysis
        sources = {}
        for action in actions:
            ip = action.get('source_ip')
            if ip:
                if ip not in sources:
                    sources[ip] = {'total': 0, 'risk_scores': []}
                sources[ip]['total'] += 1
                if 'risk_score' in action:
                    sources[ip]['risk_scores'].append(float(action['risk_score']))
        
        info(f"\n📍 SOURCE ANALYSIS:")
        for ip, stats in sources.items():
            avg_risk = sum(stats['risk_scores'])/len(stats['risk_scores']) if stats['risk_scores'] else 0
            info(f"  🖥️ {ip}: {stats['total']} events, avg risk: {avg_risk:.3f}")
        
    else:
        info("⚠️ No mitigation log found - system may not be running or no events processed")
    
    info("\n💡 VERIFICATION CHECKLIST:")
    info("  ✓ Check that low-risk sources eventually get whitelisted")
    info("  ✓ Verify rate limiting is applied for medium-risk sources")
    info("  ✓ Confirm high-risk sources are blocked and blacklisted")
    info("  ✓ Ensure blacklist timeouts escalate for repeat offenders")
    info("  ✓ Validate that false positives can recover through good behavior")
    
    info("\n🛠️ ADMIN COMMANDS TO RUN:")
    info("  python admin_interface.py analytics")
    info("  python admin_interface.py mitigations")
    info("  python admin_interface.py threats")
    info("  python admin_interface.py analyze <ip>")
    
    info("\n" + "="*80)
    info("🧪 RISK-BASED MITIGATION TESTING COMPLETED!")
    info("="*80 + "\n")



def start_network():
    topo = EnhancedTestTopology()
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

    test_risk_based_mitigations(net)

    info("\n[INFO] Network is now ready for manual testing. Entering CLI...\n")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    start_network()
