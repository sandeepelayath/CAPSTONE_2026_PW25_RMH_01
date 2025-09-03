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

def reset_controller_state():
    """Reset controller state to ensure consistent test results"""
    info("🔄 Resetting controller state for consistent testing...\n")
    # Clear any existing state files
    state_files = [
        '/tmp/traffic_history.json',
        '/tmp/blacklist.json', 
        '/tmp/whitelist.json',
        '/tmp/mitigation_actions.json',
        'controller/risk_mitigation_actions.json',
        'controller/mitigation_actions.json'
    ]
    
    for file_path in state_files:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                info(f"  ✅ Cleared {file_path}")
        except Exception as e:
            info(f"  ⚠️ Could not clear {file_path}: {e}")
    
    info("✅ Controller state reset completed\n")

def test_risk_based_mitigations(net):
    """Comprehensive test suite for all risk-based mitigation logics"""
    info("\n" + "="*80)
    info("🧪 STARTING COMPREHENSIVE RISK-BASED MITIGATION TESTS")
    info("="*80 + "\n")
    
    # Reset controller state for consistent results
    reset_controller_state()
    
    h1, h2, h3, h4, h5, h6, h7, h8 = net.get('h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'h8')
    
    # Setup services on target hosts
    setup_test_services(net)
    
    # Wait for network to stabilize and let initial connectivity be established
    info("⏳ Allowing network to stabilize and establish normal baseline traffic...\n")
    time.sleep(20)  # Increased for more stability
    
    # Clear any initial flows that might affect scoring
    info("🧹 Clearing initial network discovery flows...\n")
    time.sleep(10)
    
    # Test 1: Establish normal baseline traffic first (very low risk)
    test_baseline_traffic(h1, h2, h7)
    
    # Test 2: Low Risk Traffic (Should be allowed and potentially whitelisted)
    test_low_risk_traffic(h7, h1, h2)
    
    # Test 3: Medium Risk Traffic (Should trigger rate limiting)
    test_medium_risk_traffic(h4, h1, h2)
    
    # Test 4: High Risk Traffic (Should trigger short timeout + blacklisting)
    test_high_risk_traffic(h5, h1, h2)
    
    # Test 5: Escalating Risk Pattern (Test blacklist escalation)
    info("🚀 Starting Test 5: Escalating Risk Pattern")
    test_escalating_risk_pattern(h6, h1, h2)
    
    # Test 6: Whitelist Recovery Test (Test false positive handling)
    test_whitelist_recovery(h3, h1, h2)
    
    # Test 7: Mixed Traffic Analysis (Real-world scenario)
    test_mixed_traffic_scenario(net)
    
    # Test 8: Rate Limiting Effectiveness
    info("🚀 Starting Test 8: Rate Limiting Effectiveness")
    test_rate_limiting_effectiveness(h4, h1)
    
    # Test 9: Honeypot Tripwire Test
    info("🚀 Starting Test 9: Honeypot Tripwire Test (h6 -> honeypot)")
    test_honeypot_tripwire(h6, "10.0.0.9")
    
    # Test 10: Blacklist Learning and Decay
    info("🚀 Starting Test 10: Blacklist Learning and Decay (h8 attacks)")
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
        
        # Generate sustained high-risk traffic (not just single commands)
        info("  📡 Generating sustained nmap scanning...")
        source.cmd(f'nmap -sS -T5 -p 1-500 {target1.IP()} > /dev/null 2>&1')
        time.sleep(3)
        
        # Multiple SQL injection attempts to ensure detection
        info("  💉 Performing multiple SQL injection attempts...")
        for i in range(10):
            source.cmd(f'curl -s "http://{target2.IP()}:8081/admin?cmd=DROP%20TABLE%20users&attempt={i}" > /dev/null 2>&1')
            time.sleep(0.5)  # Brief pause between attempts
        
        # Additional high-frequency requests to ensure anomaly detection
        info("  🌐 Generating high-frequency HTTP requests...")
        for i in range(20):
            source.cmd(f'curl -s "http://{target1.IP()}:8080/attack?id={i}" > /dev/null 2>&1')
            time.sleep(0.2)
        
        # Wait for mitigation system to process
        info(f"  ⏱️ Waiting for mitigation processing...")
        time.sleep(15)
        
        info(f"✅ Round {round_num + 1} completed - timeout should be {2**(round_num+1)} times longer\n")
    
    info("✅ Escalating risk pattern test completed")
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
    """Test Case 8: Verify rate limiting effectiveness"""
    info("\n" + "="*60)
    info("📊 TEST 8: RATE LIMITING EFFECTIVENESS")
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
    """Test Case 10: Test blacklist learning and timeout escalation"""
    info("\n" + "="*60)
    info("⚫ TEST 10: BLACKLIST LEARNING AND TIMEOUT ESCALATION")
    info("="*60)
    info(f"📋 Expected: Progressive timeout increases for repeat offenders")
    info(f"🎯 Source: {source.name} ({source.IP()})")
    info(f"🎯 Targets: {target1.name}, {target2.name}\n")
    
    for attempt in range(3):
        info(f"🔄 Blacklist attempt {attempt + 1}/3...\n")
        
        # Generate sustained high-risk behavior with multiple attack vectors
        info("  💉 Performing SQL injection barrage...")
        for i in range(15):
            source.cmd(f'curl -s "http://{target1.IP()}:8080/admin?cmd=DROP%20DATABASE&id={i}" > /dev/null 2>&1')
            time.sleep(0.3)
        
        info("  🔍 Performing aggressive port scanning...")
        source.cmd(f'nmap -sS -T5 -p 1-200 {target2.IP()} > /dev/null 2>&1')
        time.sleep(2)
        
        # Additional high-frequency attack attempts
        info("  🌐 Generating attack traffic burst...")
        for i in range(25):
            source.cmd(f'curl -s "http://{target1.IP()}:8080/hack?attempt={i}" > /dev/null 2>&1')
            source.cmd(f'curl -s "http://{target2.IP()}:8081/exploit?id={i}" > /dev/null 2>&1')
            time.sleep(0.2)
        
        # Brute force simulation
        info("  🔨 Simulating brute force attack...")
        passwords = ['admin', 'password', '123456', 'root', 'qwerty', 'letmein', 'welcome', 'monkey']
        for pwd in passwords:
            for i in range(3):  # Multiple attempts per password
                source.cmd(f'curl -s "http://{target1.IP()}:8080/login?user=admin&pass={pwd}&try={i}" > /dev/null 2>&1')
                time.sleep(0.1)
        
        # Record attempt time
        attempt_time = datetime.now().isoformat()
        info(f"   📝 Attempt logged at {attempt_time}")
        
        # Wait for mitigation processing
        info("  ⏱️ Waiting for mitigation processing...")
        time.sleep(20)  # Longer wait to ensure processing
        
        expected_timeout = 60 * (2 ** attempt)  # Exponential increase
        info(f"   ⏱️ Expected timeout for this attempt: {expected_timeout} seconds\n")
    
    info("✅ Blacklist learning test completed")
    info("💡 Each successive violation should result in longer blacklist periods\n")

def test_honeypot_tripwire(source, honeypot_ip="10.0.0.9"):
    """Test Case 9: Test honeypot tripwire functionality"""
    info("\n" + "="*60)
    info("🍯 TEST 9: HONEYPOT TRIPWIRE TEST")
    info("="*60)
    info(f"📋 Expected: Immediate critical risk (1.0) and blocking")
    info(f"🎯 Source: {source.name} ({source.IP()})")
    info(f"🍯 Honeypot IP: {honeypot_ip}\n")
    
    info("🔄 Generating sustained traffic to honeypot IP...\n")
    
    # Multiple rounds of honeypot access attempts to ensure detection
    for round_num in range(3):
        info(f"  🍯 Honeypot access round {round_num + 1}/3...")
        
        # Multiple connection attempts with different protocols
        for i in range(10):
            source.cmd(f'ping -c 1 {honeypot_ip} > /dev/null 2>&1')
            time.sleep(0.1)
            source.cmd(f'curl -s --connect-timeout 1 http://{honeypot_ip}:80/ > /dev/null 2>&1')
            time.sleep(0.1)
            source.cmd(f'curl -s --connect-timeout 1 http://{honeypot_ip}:443/ > /dev/null 2>&1')
            time.sleep(0.1)
            source.cmd(f'nc -w 1 {honeypot_ip} 22 < /dev/null > /dev/null 2>&1')
            time.sleep(0.1)
            source.cmd(f'nc -w 1 {honeypot_ip} 3306 < /dev/null > /dev/null 2>&1')
            time.sleep(0.1)
        
        info(f"    📊 Sent 50 honeypot access attempts in round {round_num + 1}")
        time.sleep(2)  # Wait between rounds
    
    # Additional sustained probing to ensure flow generation
    info("  🔍 Performing sustained honeypot probing...")
    for i in range(30):
        source.cmd(f'telnet {honeypot_ip} 23 < /dev/null > /dev/null 2>&1 &')
        source.cmd(f'curl -s --max-time 1 http://{honeypot_ip}:8080/admin > /dev/null 2>&1')
        time.sleep(0.2)
    
    info("✅ Honeypot tripwire test completed")
    info("💡 This should result in immediate critical risk and blacklisting\n")
    time.sleep(10)  # Longer wait to ensure processing

def display_test_results():
    """Display comprehensive test results and system status"""
    info("\n" + "="*80)
    info("📈 COMPREHENSIVE TEST RESULTS SUMMARY")
    info("="*80 + "\n")
    
    # Check if risk mitigation log exists
    log_files = [
        '../controller/risk_mitigation_actions.json',
        '../controller/mitigation_actions.json',
        '/home/sandeep/Capstone_Phase3/controller/risk_mitigation_actions.json',
        '/home/sandeep/Capstone_Phase3/controller/mitigation_actions.json'
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



def flush_all_ports_and_flows(net):
    """Comprehensive port and flow flushing to fix connectivity issues"""
    info("\n" + "="*60)
    info("🧹 FLUSHING ALL PORTS AND FLOWS")
    info("="*60)
    
    # Step 1: Stop all OpenFlow controllers temporarily
    info("🛑 Temporarily stopping OpenFlow processing...\n")
    for switch in net.switches:
        switch.cmd('ovs-vsctl set-fail-mode', switch.name, 'standalone')
    
    time.sleep(2)
    
    # Step 2: Delete all flows from all switches
    info("🗑️ Deleting all flows from switches...\n")
    for switch in net.switches:
        info(f"  🧹 Flushing flows on {switch.name}")
        switch.cmd('ovs-ofctl del-flows', switch.name)
        switch.cmd('ovs-ofctl del-meters', switch.name)  # Also clear meters
        
        # Show current flow count
        result = switch.cmd('ovs-ofctl dump-flows', switch.name, '| wc -l')
        info(f"    📊 Remaining flows: {result.strip()}")
    
    # Step 3: Clear ARP tables on all hosts
    info("\n🗂️ Clearing ARP tables on all hosts...\n")
    for host in net.hosts:
        info(f"  🧹 Clearing ARP on {host.name}")
        host.cmd('ip neigh flush all')
        host.cmd('arp -d -a')  # Fallback for older systems
    
    # Step 4: Restart interfaces to clear any stuck states
    info("\n🔄 Restarting network interfaces...\n")
    for host in net.hosts:
        intf_name = f"{host.name}-eth0"
        info(f"  🔄 Restarting {intf_name}")
        host.cmd(f'ifconfig {intf_name} down')
        time.sleep(0.5)
        host.cmd(f'ifconfig {intf_name} up')
    
    # Step 5: Flush bridge tables
    info("\n🌉 Flushing bridge MAC tables...\n")
    for switch in net.switches:
        info(f"  🧹 Flushing MAC table on {switch.name}")
        switch.cmd('ovs-appctl fdb/flush', switch.name)
    
    # Step 6: Re-enable OpenFlow with clean state
    info("\n🔄 Re-enabling OpenFlow control...\n")
    for switch in net.switches:
        switch.cmd('ovs-vsctl set-fail-mode', switch.name, 'secure')
        switch.cmd('ovs-vsctl set-controller', switch.name, 'tcp:127.0.0.1:6653')
    
    # Step 7: Install basic connectivity flows before controller takes over
    info("\n📡 Installing basic connectivity flows...\n")
    for switch in net.switches:
        # Allow ARP traffic
        switch.cmd('ovs-ofctl add-flow', switch.name, 'arp,priority=1000,actions=flood')
        # Allow DHCP if needed
        switch.cmd('ovs-ofctl add-flow', switch.name, 'udp,tp_dst=67,priority=1000,actions=flood')
        switch.cmd('ovs-ofctl add-flow', switch.name, 'udp,tp_dst=68,priority=1000,actions=flood')
    
    time.sleep(3)
    
    info("✅ Port and flow flushing completed!\n")
    
    # Step 8: Test basic connectivity
    info("🔍 Testing basic connectivity after flush...\n")
    test_basic_connectivity(net)

def test_basic_connectivity(net):
    """Test basic connectivity after flushing"""
    info("📡 Performing connectivity tests...\n")
    
    # Get first two hosts for testing
    h1, h2 = net.hosts[0], net.hosts[1]
    
    # Test 1: Ping between directly connected hosts
    info(f"  🏓 Testing ping: {h1.name} -> {h2.name}")
    result = h1.cmd(f'ping -c 3 -W 2 {h2.IP()}')
    if "3 received" in result:
        info("    ✅ Ping successful")
    else:
        info("    ❌ Ping failed")
        info(f"    📝 Result: {result}")
    
    # Test 2: ARP resolution
    info(f"  🗂️ Testing ARP resolution")
    h1.cmd(f'ping -c 1 {h2.IP()} > /dev/null 2>&1')  # Generate ARP
    arp_result = h1.cmd('arp -a')
    if h2.IP() in arp_result:
        info("    ✅ ARP resolution working")
    else:
        info("    ❌ ARP resolution failed")
        info(f"    📝 ARP table: {arp_result}")
    
    # Test 3: Check switch flow tables
    info(f"  📊 Checking flow tables...")
    for switch in net.switches:
        flows = switch.cmd('ovs-ofctl dump-flows', switch.name)
        flow_count = len([l for l in flows.split('\n') if 'actions=' in l])
        info(f"    📋 {switch.name}: {flow_count} flows")

def emergency_connectivity_fix(net):
    """Emergency fix for connectivity issues"""
    info("\n" + "="*60)
    info("🚨 EMERGENCY CONNECTIVITY FIX")
    info("="*60)
    
    # Nuclear option: Reset everything to learning switch mode
    for switch in net.switches:
        info(f"🔄 Resetting {switch.name} to learning switch mode")
        
        # Delete everything
        switch.cmd('ovs-ofctl del-flows', switch.name)
        switch.cmd('ovs-ofctl del-meters', switch.name)
        
        # Install simple learning switch flow
        switch.cmd('ovs-ofctl add-flow', switch.name, 'priority=0,actions=flood')
        
        # Allow all ARP
        switch.cmd('ovs-ofctl add-flow', switch.name, 'arp,priority=1000,actions=flood')
        
        # Set to standalone mode temporarily
        switch.cmd('ovs-vsctl set-fail-mode', switch.name, 'standalone')
    
    time.sleep(2)
    
    # Clear everything and restart
    for host in net.hosts:
        host.cmd('ip neigh flush all')
    
    info("🔄 Reconnecting to controller...")
    for switch in net.switches:
        switch.cmd('ovs-vsctl set-fail-mode', switch.name, 'secure')
    
    time.sleep(3)
    info("✅ Emergency fix completed - try pinging now!")

def add_cli_helpers():
    """Add helper commands to CLI environment"""
    return {
        'flush_ports': flush_all_ports_and_flows,
        'fix_connectivity': emergency_connectivity_fix,
        'test_ping': test_basic_connectivity,
        'clear_flows': lambda net: [s.cmd('ovs-ofctl del-flows', s.name) for s in net.switches],
        'show_flows': lambda net: [print(f"\n{s.name}:\n{s.cmd('ovs-ofctl dump-flows', s.name)}") for s in net.switches],
        'show_ports': lambda net: [print(f"\n{s.name}:\n{s.cmd('ovs-ofctl show', s.name)}") for s in net.switches],
        'flush_arp': lambda net: [h.cmd('ip neigh flush all') for h in net.hosts]
    }

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
    
    # Configure OpenFlow 1.3
    for switch in net.switches:
        info(f"[INFO] Configuring {switch.name} for OpenFlow 1.3\n")
        switch.cmd('ovs-vsctl set bridge', switch.name, 'protocols=OpenFlow13')

    # Initial flow cleanup
    flush_all_ports_and_flows(net)

    start_packet_capture(net)
    
    # Test connectivity before starting tests
    info("\n[INFO] Testing initial network connectivity...\n")
    net.pingAll()

    reset_controller_state()
    
    # Add helper functions to CLI
    helpers = add_cli_helpers()
    
    info("\n[INFO] 🛠️ AVAILABLE CLI COMMANDS:")
    info("  flush_ports(net)     - Complete port and flow flush")
    info("  fix_connectivity(net) - Emergency connectivity fix")
    info("  test_ping(net)       - Test basic connectivity")
    info("  clear_flows(net)     - Clear all OpenFlow rules")
    info("  show_flows(net)      - Display all flows")
    info("  show_ports(net)      - Show port status")
    info("  flush_arp(net)       - Clear ARP tables")
    info("  net.pingAll()        - Test connectivity between all hosts")
    
    # Run comprehensive tests
    test_risk_based_mitigations(net)

    info("\n[INFO] Network is now ready for manual testing. Entering CLI...\n")
    info("💡 If pings don't work, try: flush_ports(net) or fix_connectivity(net)\n")
    
    # Make helpers available in CLI
    import __main__
    for name, func in helpers.items():
        setattr(__main__, name, func)
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    start_network()
