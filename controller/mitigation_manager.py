#!/usr/bin/env python3
"""
Advanced Risk-Based Network Security Mitigation Manager

This module provides a comprehensive, ML-driven network security mitigation system
for Software-Defined Networks (SDN). It implements intelligent risk assessment,
graduated response mechanisms, and adaptive learning to protect network infrastructure
from various cyber threats while minimizing false positives and service disruption.

Key Features:
- Multi-tier risk assessment with ML confidence integration
- Graduated mitigation responses (allow, rate-limit, redirect, block)
- Adaptive blacklist/whitelist management with trust scoring
- Honeypot integration for advanced threat detection
- OpenFlow meter-based rate limiting and QoS enforcement
- Real-time threat analysis with behavioral pattern recognition
- Administrative interfaces for manual security policy management
- Comprehensive audit logging and performance metrics

Architecture:
- Risk Scoring: Combines ML confidence with contextual factors (frequency, reputation)
- Mitigation Tiers: Low Risk (allow/whitelist) → Medium Risk (rate limit) → High Risk (redirect/block)
- Adaptive Learning: Dynamic blacklist/whitelist management with time-based trust decay
- Honeypot Tripwires: Immediate maximum penalty for honeypot access attempts
- Flow Control: OpenFlow 1.3 meter tables for precise bandwidth and packet rate limiting

Security Policies:
- Configurable risk thresholds for adaptive threat response sensitivity
- Escalating timeout periods for repeat offenders with exponential backoff
- False positive mitigation through whitelist recovery mechanisms
- Administrative override capabilities for security operations teams

Dependencies:
- Ryu SDN controller framework for OpenFlow communication
- Python threading for concurrent monitoring and management
- JSON logging for security audit trails and incident response

Author: Capstone Project Team  
Version: 2.0 
Date: 2025 Oct 9
"""

import time
import json
import threading
import math
import re
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging


class RiskBasedMitigationManager:
    """
    Intelligent Network Security Mitigation Manager with ML-Driven Risk Assessment
    
    This class implements a comprehensive security mitigation system for SDN environments,
    combining machine learning-based threat detection with adaptive response mechanisms.
    It provides multi-tier protection through risk-based decision making, graduated
    mitigation responses, and intelligent learning from network behavior patterns.
    
    The system operates on a risk-scoring model that combines ML confidence scores with
    contextual factors including traffic frequency, historical behavior, and reputation
    scoring. Mitigation responses are graduated from passive monitoring through rate
    limiting to complete traffic blocking based on calculated risk levels.
    
    Key Components:
    - Risk Assessment Engine: Calculates comprehensive risk scores from multiple factors
    - Mitigation Response System: Applies graduated responses based on risk levels  
    - Adaptive Learning: Maintains blacklist/whitelist with trust-based scoring
    - Honeypot Integration: Immediate threat response for honeypot access attempts
    - Administrative Interface: Manual security policy management and overrides
    
    Attributes:
        controller (RyuController): Reference to the main SDN controller instance
        risk_profiles (dict): Comprehensive risk assessment data per source IP
        blacklist (dict): Temporary blacklist with offense tracking and escalation
        whitelist (dict): Trusted sources with time-based trust decay mechanisms
        rate_limited_sources (dict): Active rate limiting configurations per source
        honeypot_ips (set): Configured honeypot IP addresses for tripwire detection
        meter_registry (dict): OpenFlow meter allocation tracking per datapath
    """
    
    def __init__(self, controller_ref, 
                 low_risk_threshold=0.08, medium_risk_threshold=0.18, high_risk_threshold=0.25,
                 base_rate_limit_pps=1000, base_rate_limit_bps=1000000,
                 base_blacklist_timeout=60, max_blacklist_timeout=3600,
                 whitelist_duration=86400, whitelist_decay_rate=0.1,
                 block_duration=300, analysis_window=60):
        """
        Initialize the Risk-Based Mitigation Manager with production-tuned parameters.
        
        Sets up the complete security mitigation infrastructure including risk assessment
        thresholds, rate limiting configurations, blacklist/whitelist management, and
        honeypot integration. All parameters are production-tuned for optimal security
        effectiveness while minimizing false positives and service disruption.
        
        Risk Threshold Configuration:
        - Low Risk (< 0.08): Allow traffic, consider for whitelisting
        - Medium Risk (0.08-0.18): Apply adaptive rate limiting based on risk granularity  
        - High Risk (0.18-0.25): Redirect to honeypot for behavior analysis
        - Critical Risk (≥ 0.25): Immediate blocking with blacklist escalation
        
        Rate Limiting Strategy:
        - Uses OpenFlow meter tables for precise bandwidth and packet rate control
        - Adaptive throttling based on risk score granularity within medium risk tier
        - Automatic removal when sustained low-risk behavior is observed
        
        Blacklist/Whitelist Learning:
        - Exponential timeout escalation for repeat offenders (max 1 hour)
        - Trust-based whitelist scoring with configurable time decay
        - Administrative override capabilities for security operations
        
        Args:
            controller_ref (RyuController): Reference to the main SDN controller instance
            low_risk_threshold (float): Risk threshold for low/medium boundary (0.08)
            medium_risk_threshold (float): Risk threshold for medium/high boundary (0.18)
            high_risk_threshold (float): Risk threshold for high/critical boundary (0.25)
            base_rate_limit_pps (int): Base packet rate limit in packets/second (1000)
            base_rate_limit_bps (int): Base bandwidth limit in bytes/second (1MB)
            base_blacklist_timeout (int): Initial blacklist timeout in seconds (60s)
            max_blacklist_timeout (int): Maximum blacklist timeout in seconds (1 hour)
            whitelist_duration (int): Initial whitelist validity period in seconds (24 hours)
            whitelist_decay_rate (float): Hourly trust decay rate for whitelist entries (0.1)
            block_duration (int): Legacy blocking duration for backward compatibility (300s)
            analysis_window (int): Traffic behavior analysis window in seconds (60s)
        """
        # Core system integration and configuration
        self.controller = controller_ref  # Reference to main SDN controller
        self.analysis_window = analysis_window  # Traffic behavior analysis timeframe
        
        # Multi-tier risk assessment thresholds (production-tuned for optimal security)
        self.low_risk_threshold = low_risk_threshold      # Below this: Allow traffic, consider whitelisting
        self.medium_risk_threshold = medium_risk_threshold # Below this: Apply rate limiting
        self.threat_threshold = medium_risk_threshold      # Legacy threat detection threshold
        self.high_risk_threshold = high_risk_threshold     # Above this: Critical risk, immediate blocking
        
        # OpenFlow-based rate limiting configuration
        self.base_rate_limit_pps = base_rate_limit_pps  # Base packet rate limit (packets/second)
        self.base_rate_limit_bps = base_rate_limit_bps  # Base bandwidth limit (bytes/second)
        
        # Adaptive blacklist management with escalation
        self.base_blacklist_timeout = base_blacklist_timeout  # Initial blacklist duration
        self.max_blacklist_timeout = max_blacklist_timeout    # Maximum escalated timeout
        
        # Trust-based whitelist management with decay
        self.whitelist_duration = whitelist_duration      # Initial whitelist validity period  
        self.whitelist_decay_rate = whitelist_decay_rate  # Hourly trust score decay rate
        
        # Honeypot tripwire configuration for advanced threat detection
        self.honeypot_ips = {'10.0.0.9', '10.0.0.10'}  # Non-existent decoy hosts for threat detection
        self.honeypot_hits = defaultdict(int)           # Counter for honeypot access attempts per source
        
        # Core security tracking and management data structures
        self.risk_profiles = {}                    # Comprehensive risk assessment per source IP
        self.blacklist = {}                       # Temporary blacklist with offense escalation tracking
        self.whitelist = {}                       # Trusted sources with time-based trust scoring
        self.rate_limited_sources = {}            # Active rate limiting configurations per source
        self.traffic_history = defaultdict(deque) # Sliding window of traffic records per source
        self.anomaly_counts = defaultdict(int)    # Legacy anomaly counters per source
        self.meter_registry = {}                  # OpenFlow meter allocation tracking per datapath
        
        # Legacy compatibility structures for existing integrations
        self.blocked_sources = {}                 # Legacy blocking interface compatibility
        self.legitimate_behavior = defaultdict(list)  # Historical legitimate behavior patterns
        
        # Initialize comprehensive logging system for security audit trails
        self.setup_logging()
        
        # Launch background monitoring and maintenance thread
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._background_monitor, name="SecurityMonitor")
        self.monitor_thread.daemon = True  # Ensures clean shutdown with main process
        self.monitor_thread.start()
        
        self.logger.info("🛡️ Risk-Based Mitigation Manager initialized successfully")
        self.logger.info(f"   Risk Thresholds: LOW < {low_risk_threshold}, MEDIUM < {medium_risk_threshold}, HIGH < {high_risk_threshold}")
        self.logger.info(f"   Rate Limits: {base_rate_limit_pps} pps, {base_rate_limit_bps//1000} Kbps")
        self.logger.info(f"   Honeypot IPs: {', '.join(self.honeypot_ips)}")

    def setup_logging(self):
        """
        Initialize comprehensive security logging system for audit trails and incident response.
        
        Configures dual-output logging with console display for real-time monitoring and
        file-based persistent logging for security audit trails. The logging system supports
        compliance requirements and provides detailed records for forensic analysis.
        
        Logging Configuration:
        - Console Handler: Real-time security events for SOC monitoring
        - File Handler: Persistent audit logs for compliance and incident response
        - Structured Formatting: Timestamp, severity, and detailed message content
        - Thread-Safe Operation: Safe for concurrent access from multiple threads
        """
        self.logger = logging.getLogger('RiskBasedMitigationManager')
        self.logger.setLevel(logging.INFO)
        
        # Prevent duplicate handlers during system reinitializations
        if self.logger.handlers:
            return
        
        # Console handler for real-time Security Operations Center (SOC) monitoring
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(logging.INFO)
        self.logger.addHandler(console_handler)
        
        # File handler for persistent security audit trails and compliance logging
        file_handler = logging.FileHandler('risk_mitigation_log.json')
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(logging.INFO)
        self.logger.addHandler(file_handler)

    def risk_based_mitigation(self, flow_stats, ml_confidence, source_ip=None, dest_ip=None, flow_id=None):
        """
        Primary entry point for ML-based network security risk assessment and mitigation.
        
        Implements intelligent risk assessment combining machine learning threat detection 
        with contextual behavioral analysis. This method focuses purely on ML-based risk 
        assessment after initial security policy checks have been performed elsewhere.
        Applies graduated mitigation responses based on calculated risk levels.
        
        Mitigation Decision Flow:
        1. Source Identification: Extract network identifiers (IP/MAC) from flow statistics
        2. Risk Assessment: Calculate comprehensive risk score from ML confidence and context
        3. Mitigation Application: Apply graduated response based on risk level
        4. Audit Logging: Record all security actions for compliance and analysis
        
        Note: Security policy checks (whitelist, blacklist, honeypot) should be performed
        via evaluate_flow_security() before calling this method to avoid redundancy.
        
        Risk-Based Response Tiers:
        - Low Risk: Allow traffic, consider for trusted whitelist inclusion
        - Medium Risk: Apply adaptive rate limiting based on risk granularity
        - High Risk: Redirect to honeypot for behavioral analysis
        - Critical Risk: Immediate blocking with escalating blacklist penalties
        
        Args:
            flow_stats (OFPFlowStats): OpenFlow flow statistics containing traffic metadata
            ml_confidence (float): Machine learning model confidence score (0.0 to 1.0)
            source_ip (str, optional): Source IP address if pre-extracted from flow
            dest_ip (str, optional): Destination IP address for honeypot detection
            flow_id (str, optional): Unique flow identifier for granular tracking
            
        Returns:
            dict: Mitigation action details including action type, risk level, and parameters
                 None if mitigation fails or no action required
        """
        try:
            # Extract source IP for ML-based risk assessment
            if not source_ip:
                source_ip = self._extract_source_ip(flow_stats)

            # Execute comprehensive risk-based mitigation pipeline
            if source_ip:
                # Calculate multi-factor risk score combining ML confidence with contextual intelligence
                risk_score = self._calculate_risk_score(source_ip, ml_confidence, flow_stats)
                
                # Update comprehensive risk profile for continuous learning and trend analysis
                self._update_risk_profile(source_ip, risk_score, ml_confidence, flow_stats)
                
                # Apply graduated mitigation response based on calculated risk level
                mitigation_action = self._apply_graduated_mitigation(source_ip, risk_score, flow_stats)
                
                # Generate comprehensive audit log for compliance and incident response
                self._log_risk_action(source_ip, risk_score, mitigation_action, flow_stats)
                
                return mitigation_action

            # Log failed mitigation attempts for security monitoring and system debugging
            self.logger.warning("⚠️ Anomalous flow detected but source identification failed - possible L2/non-IP traffic")
            self._log_failed_mitigation(flow_stats, ml_confidence, "source_identification_failed")
            return None
            
        except Exception as e:
            self.logger.error(f"❌ Error in risk-based mitigation: {e}")
            return None

    def log_l2_anomaly(self, source_mac, confidence, flow_stats):
        """
        Log Layer 2 network anomalies for non-IP traffic monitoring.
        
        Records anomalous behavior detected at the data link layer (Layer 2) where
        traditional IP-based mitigation cannot be applied. Attempts MAC-to-IP resolution
        through the controller's ARP table for enhanced visibility and potential
        correlation with IP-based security events.
        
        Use Cases:
        - ARP spoofing/poisoning detection
        - MAC flooding attack monitoring  
        - Bridge protocol anomalies
        - Non-IP malicious traffic patterns
        
        Args:
            source_mac (str): Source MAC address of anomalous L2 traffic
            confidence (float): ML model confidence score for the anomaly
            flow_stats (OFPFlowStats): OpenFlow statistics for the anomalous flow
        """
        # Attempt MAC-to-IP resolution for enhanced visibility
        source_ip = self.controller.mac_to_ip.get(source_mac, "Unknown")
        
        self.logger.info(f"📡 L2 ANOMALY: MAC {source_mac} (Resolved IP: {source_ip}, Confidence: {confidence:.3f})")
        
        # Generate structured log entry for L2 security monitoring
        log_entry = {
            'action_type': 'L2_ANOMALY_DETECTED',
            'source_mac': source_mac,
            'source_ip': source_ip,
            'timestamp': datetime.now().isoformat(),
            'ml_confidence': confidence,
            'details': 'Layer 2 anomaly detected - IP-based mitigation not applicable',
            'packet_count': getattr(flow_stats, 'packet_count', 0),
            'byte_count': getattr(flow_stats, 'byte_count', 0)
        }
        self._write_log_entry(log_entry)

    def log_unidentified_anomaly(self, confidence, flow_stats):
        """
        Log network anomalies where source identification failed for forensic analysis.
        
        Records anomalous network behavior where neither IP nor MAC source identification
        was possible. These events may indicate advanced evasion techniques, protocol
        anomalies, or potential zero-day attack vectors requiring manual analysis.
        
        Potential Causes:
        - Malformed packet headers or protocol violations
        - Advanced evasion techniques bypassing normal identification
        - Encrypted tunnel traffic anomalies
        - Novel attack vectors or zero-day exploits
        
        Args:
            confidence (float): ML model confidence score for the detected anomaly
            flow_stats (OFPFlowStats): OpenFlow statistics for the unidentified anomalous flow
        """
        self.logger.warning(f"🔍 UNIDENTIFIED ANOMALY: High-confidence threat without source identification (Confidence: {confidence:.3f})")
        
        # Generate forensic log entry for security analyst review
        log_entry = {
            'action_type': 'UNIDENTIFIED_ANOMALY',
            'timestamp': datetime.now().isoformat(),
            'ml_confidence': confidence,
            'details': 'High-confidence anomaly without source identification - requires analyst review',
            'packet_count': getattr(flow_stats, 'packet_count', 0),
            'byte_count': getattr(flow_stats, 'byte_count', 0),
            'flow_match': str(getattr(flow_stats, 'match', 'Unknown'))
        }
        self._write_log_entry(log_entry)

    def _calculate_risk_score(self, source_ip, ml_confidence, flow_stats):
        """
        Calculate comprehensive multi-factor risk score for intelligent threat assessment.
        
        Combines machine learning confidence with contextual behavioral analysis and
        reputation intelligence to produce a holistic risk assessment. The weighted
        formula balances immediate threat detection with historical behavioral patterns
        and known reputation indicators for optimal security decision making.
        
        Risk Score Formula (0.0 to 1.0):
        - ML Confidence Factor (70%): Primary threat detection from trained models
        - Frequency Factor (20%): Recent anomalous behavior patterns within 5-minute window  
        - Reputation Factor (10%): Historical blacklist/whitelist status and trust scoring
        
        Contextual Intelligence:
        - Only counts verified anomalous flows for frequency analysis
        - Applies exponential frequency normalization to prevent score saturation
        - Integrates adaptive reputation scoring with trust decay mechanisms
        
        Args:
            source_ip (str): Source IP address for risk assessment
            ml_confidence (float): Machine learning model confidence score (0.0 to 1.0)
            flow_stats (OFPFlowStats): Flow statistics for contextual analysis
            
        Returns:
            float: Comprehensive risk score (0.0 to 1.0) for mitigation decision making
        """
        # Primary Risk Factor: ML Threat Detection Confidence (70% weighting)
        ml_factor = ml_confidence * 0.7

        # Secondary Risk Factor: Recent Anomalous Behavior Frequency (20% weighting)
        # Analyzes frequency of verified anomalous flows within 5-minute sliding window
        recent_time = datetime.now() - timedelta(minutes=5)
        recent_anomalous_flows = [r for r in self.traffic_history[source_ip]
                                  if self._parse_timestamp(r['timestamp']) > recent_time and r.get('anomalous', False)]
        # Exponential normalization prevents score saturation (capped at 10 anomalies = 100% frequency factor)
        frequency_factor = min(len(recent_anomalous_flows) / 10.0, 1.0) * 0.2

        # Tertiary Risk Factor: Historical Reputation Intelligence (10% weighting)
        # Incorporates blacklist/whitelist status with trust decay mechanisms
        reputation_factor = self._calculate_reputation_factor(source_ip) * 0.1

        # Synthesize final comprehensive risk score with bounds enforcement
        risk_score = ml_factor + frequency_factor + reputation_factor
        risk_score = max(0.0, min(1.0, risk_score))  # Enforce [0.0, 1.0] bounds

        # Generate detailed risk assessment audit log for security analysis
        self.logger.info(f"🎯 RISK ASSESSMENT: {source_ip} → Total={risk_score:.3f} "
                         f"[ML={ml_factor:.3f}, Freq={frequency_factor:.3f}, Rep={reputation_factor:.3f}] "
                         f"Thresholds: L<{self.low_risk_threshold}, M<{self.medium_risk_threshold}, H<{self.high_risk_threshold}")

        return risk_score

    def _calculate_reputation_factor(self, source_ip):
        """
        Calculate reputation-based risk adjustment from historical security intelligence.
        
        Analyzes historical blacklist/whitelist status to provide reputation-based risk
        modification. Active blacklist entries increase risk based on offense escalation,
        while trusted whitelist entries with high trust scores reduce risk assessment.
        
        Reputation Scoring Logic:
        - Blacklisted Sources: Risk increase based on offense count (normalized to max 5 offenses)
        - Whitelisted Sources: Risk reduction based on current trust score (min 50% trust required)
        - Unknown Sources: Neutral reputation factor (no adjustment)
        
        Args:
            source_ip (str): Source IP address for reputation analysis
            
        Returns:
            float: Reputation factor (-1.0 to +1.0) for risk score adjustment
        """
        # Active blacklist status increases risk based on offense escalation
        if source_ip in self.blacklist:
            blacklist_entry = self.blacklist[source_ip]
            if datetime.now() < blacklist_entry['expiry']:
                # Normalize offense count to prevent extreme risk inflation (max 5 offenses = 100% increase)
                return min(blacklist_entry['offense_count'] / 5.0, 1.0)
        
        # Active whitelist status reduces risk based on current trust level
        if source_ip in self.whitelist:
            whitelist_entry = self.whitelist[source_ip]
            trust_score = self._calculate_whitelist_trust(whitelist_entry)
            if trust_score > 0.5:  # Minimum 50% trust required for risk reduction
                # Apply proportional risk reduction based on trust level
                return -0.5 * trust_score
        
        return 0.0  # Neutral reputation for unknown sources

    def _apply_graduated_mitigation(self, source_ip, risk_score, flow_stats):
        """
        Apply intelligent graduated mitigation response based on comprehensive risk assessment.
        
        Implements a four-tier graduated response system that balances security effectiveness
        with network performance and service availability. Each tier provides progressively
        stronger security measures while maintaining operational continuity for legitimate traffic.
        
        Graduated Response Tiers:
        - Tier 1 (Low Risk): Allow traffic, monitor for whitelist consideration
        - Tier 2 (Medium Risk): Apply adaptive OpenFlow-based rate limiting
        - Tier 3 (High Risk): Redirect to honeypot for behavioral analysis
        - Tier 4 (Critical Risk): Immediate blocking with blacklist escalation
        
        The system automatically selects the appropriate response tier based on calculated
        risk scores and applies the corresponding mitigation strategy with detailed logging.
        
        Args:
            source_ip (str): Source IP address requiring mitigation response
            risk_score (float): Calculated comprehensive risk score (0.0 to 1.0)
            flow_stats (OFPFlowStats): Flow statistics for contextual mitigation decisions
            
        Returns:
            dict: Detailed mitigation action specification including type, parameters, and metadata
        """
        current_time = datetime.now()
        
        self.logger.info(f"🎯 MITIGATION SELECTION: {source_ip} → Risk={risk_score:.3f} "
                        f"[Thresholds: L<{self.low_risk_threshold}, M<{self.medium_risk_threshold}, H<{self.high_risk_threshold}]")
        
        # Tier 1: Low Risk - Allow with Monitoring and Whitelist Consideration
        if risk_score < self.low_risk_threshold:
            action = self._handle_low_risk(source_ip, risk_score, flow_stats)
            
        # Tier 2: Medium Risk - Adaptive Rate Limiting with OpenFlow Meters
        elif risk_score < self.medium_risk_threshold:
            action = self._handle_medium_risk(source_ip, risk_score, flow_stats)
            
        # Tier 3: High Risk - Honeypot Redirection for Behavioral Analysis
        elif risk_score < self.high_risk_threshold:
            action = {
                'action': 'REDIRECT_TO_HONEYPOT',
                'risk_level': 'HIGH', 
                'risk_score': risk_score,
                'target_honeypot': list(self.honeypot_ips)[0] if self.honeypot_ips else None,
                'details': f'High-risk traffic redirected to honeypot for behavioral analysis'
            }
            
        # Tier 4: Critical Risk - Immediate Blocking with Blacklist Escalation
        else:
            action = self._handle_high_risk(source_ip, risk_score, flow_stats)
            
        return action

    def _handle_low_risk(self, source_ip, risk_score, flow_stats):
        """
        Handle low-risk traffic with monitoring and whitelist consideration.
        
        Processes traffic assessed as low security risk by allowing normal flow
        processing while monitoring for consistent legitimate behavior patterns.
        Automatically removes any existing restrictive measures and evaluates
        the source for trusted whitelist inclusion based on sustained good behavior.
        
        Low-Risk Response Actions:
        1. Remove any existing rate limiting restrictions
        2. Allow normal traffic processing with continued monitoring
        3. Evaluate for whitelist inclusion based on behavior consistency
        4. Log security decision for audit trail compliance
        
        Args:
            source_ip (str): Source IP address with low risk assessment
            risk_score (float): Calculated low risk score for documentation
            flow_stats (OFPFlowStats): Flow statistics for behavioral analysis
            
        Returns:
            dict: Allow action specification with monitoring continuation details
        """
        # Remove any existing security restrictions for low-risk sources
        if source_ip in self.rate_limited_sources:
            self._remove_rate_limiting(source_ip)
            self.logger.info(f"📈 Removed rate limiting for low-risk source: {source_ip}")
            
        # Evaluate for trusted whitelist inclusion based on sustained low-risk behavior
        recent_low_risk_count = self._count_recent_low_risk_flows(source_ip)
        if recent_low_risk_count >= 10:  # Require 10 consecutive low-risk flows for trust
            self._add_to_whitelist(source_ip, "Sustained low-risk behavior pattern")
            
        self.logger.info(f"✅ LOW RISK ALLOW: {source_ip} → Risk={risk_score:.3f} (Monitoring continues)")
        
        return {
            'action': 'ALLOW',
            'risk_level': self._get_risk_level(risk_score),
            'risk_score': risk_score,
            'consecutive_low_risk_flows': recent_low_risk_count,
            'details': 'Traffic allowed with continued behavioral monitoring'
        }

    def _handle_medium_risk(self, source_ip, risk_score, flow_stats):
        """
        Handle medium-risk traffic with adaptive OpenFlow-based rate limiting.
        
        Applies intelligent traffic throttling for sources assessed as medium security risk.
        Uses OpenFlow meter tables to implement precise packet and bandwidth rate limiting
        while maintaining service availability. The rate limiting is adaptive, with
        throttling intensity proportional to the specific risk score within the medium tier.
        
        Medium-Risk Mitigation Strategy:
        1. Calculate adaptive rate limits based on risk score granularity
        2. Deploy OpenFlow meters for precise traffic control
        3. Install flow rules with meter-based rate limiting
        4. Monitor effectiveness and adjust as needed
        5. Log detailed mitigation parameters for audit compliance
        
        Rate Limiting Mechanics:
        - Packet Rate Control: Limits packets per second using OpenFlow OFPMF_PKTPS
        - Bandwidth Control: Limits bytes per second for traffic shaping
        - Adaptive Scaling: Rate limits scale inversely with risk score intensity
        - Automatic Removal: Lifted when sustained low-risk behavior observed
        
        Args:
            source_ip (str): Source IP address requiring rate limiting mitigation
            risk_score (float): Medium-tier risk score for adaptive rate calculation
            flow_stats (OFPFlowStats): Flow statistics for rate limiting context
            
        Returns:
            dict: Rate limiting action specification with applied limits and parameters
        """
        # Calculate risk-proportional rate limiting multiplier for adaptive throttling
        rate_multiplier = self._calculate_rate_limit_multiplier(risk_score)
        pps_limit = int(self.base_rate_limit_pps * rate_multiplier)
        bps_limit = int(self.base_rate_limit_bps * rate_multiplier)
        
        # Deploy OpenFlow-based adaptive rate limiting infrastructure
        self._apply_rate_limiting(source_ip, pps_limit, bps_limit, risk_score)
        
        self.logger.warning(f"⚠️ MEDIUM RISK THROTTLE: {source_ip} → Risk={risk_score:.3f} "
                           f"Limits: {pps_limit} pps, {bps_limit//1000} Kbps ({rate_multiplier*100:.0f}% capacity)")
        
        return {
            'action': 'RATE_LIMIT',
            'risk_level': self._get_risk_level(risk_score),
            'risk_score': risk_score,
            'pps_limit': pps_limit,
            'bps_limit': bps_limit,
            'rate_multiplier': rate_multiplier,
            'details': f'Adaptive rate limiting at {rate_multiplier*100:.1f}% capacity based on risk assessment'
        }

    def _handle_high_risk(self, source_ip, risk_score, flow_stats, is_honeypot_hit=False):
        """
        Handle high-risk and critical traffic with immediate blocking and blacklist escalation.
        
        Implements the most restrictive security response for sources assessed as high or critical
        risk to network security. Applies immediate traffic blocking with adaptive timeout duration
        and automatic blacklist inclusion with offense escalation tracking for repeat offenders.
        
        High-Risk Security Response:
        1. Calculate adaptive timeout duration based on risk level and offense history
        2. Deploy immediate OpenFlow blocking rules across all network switches  
        3. Add source to escalating blacklist with automatic timeout progression
        4. Apply maximum penalties for honeypot access attempts
        5. Generate comprehensive security incident logs for SOC analysis
        
        Escalation Mechanics:
        - First Offense: Base timeout duration (60 seconds default)
        - Repeat Offenses: Exponential escalation up to maximum (1 hour)
        - Honeypot Hits: Immediate maximum penalty bypass of normal escalation
        - Automatic Expiry: Blocking rules expire automatically via hard timeout
        
        Args:
            source_ip (str): Source IP address requiring immediate blocking
            risk_score (float): High/critical risk score triggering maximum response
            flow_stats (OFPFlowStats): Flow statistics for incident documentation
            is_honeypot_hit (bool): Flag for honeypot access attempt (maximum penalty)
            
        Returns:
            dict: Blocking action specification with timeout and blacklist details
        """
        # Calculate adaptive timeout with escalation for repeat offenders
        timeout_duration = self._calculate_adaptive_timeout(source_ip, risk_score, is_honeypot_hit)
        
        # Deploy immediate network-wide blocking infrastructure
        self._apply_short_timeout_block(source_ip, timeout_duration, risk_score)
        
        # Add to escalating blacklist with offense tracking and reputation impact
        self._add_to_blacklist(source_ip, timeout_duration, risk_score)
        
        # Generate incident classification details
        details = f'Immediate blocking for {timeout_duration}s with blacklist escalation'
        incident_type = 'HIGH_RISK_BLOCK'
        if is_honeypot_hit:
            details = f'HONEYPOT ACCESS DETECTED - {details}'
            incident_type = 'HONEYPOT_TRIPWIRE'
            
        self.logger.error(f"🚨 {incident_type}: {source_ip} → Risk={risk_score:.3f} "
                         f"Block={timeout_duration}s, Honeypot={is_honeypot_hit}")
        
        return {
            'action': 'SHORT_TIMEOUT_BLOCK',
            'risk_level': self._get_risk_level(risk_score),
            'risk_score': risk_score,
            'timeout_duration': timeout_duration,
            'incident_type': incident_type,
            'is_honeypot_hit': is_honeypot_hit,
            'details': details
        }

    def _get_risk_level(self, risk_score):
        """
        Convert numerical risk score to categorical security risk level classification.
        
        Translates continuous risk scores into discrete security categories for
        consistent threat classification, reporting, and incident response procedures.
        These categories align with standard cybersecurity frameworks and enable
        automated escalation procedures based on organizational security policies.
        
        Risk Level Categories:
        - LOW: Minimal threat, normal processing with monitoring
        - MEDIUM: Elevated risk, apply traffic throttling and enhanced monitoring  
        - HIGH: Significant threat, redirect to honeypot for behavioral analysis
        - CRITICAL: Severe threat, immediate blocking with blacklist escalation
        
        Args:
            risk_score (float): Numerical risk score (0.0 to 1.0)
            
        Returns:
            str: Categorical risk level for security classification and response
        """
        if risk_score < self.low_risk_threshold:
            return 'LOW'
        elif risk_score < self.medium_risk_threshold:
            return 'MEDIUM'
        elif risk_score < self.high_risk_threshold:
            return 'HIGH'
        else:
            return 'CRITICAL'
    def _calculate_rate_limit_multiplier(self, risk_score):
        """Calculate rate limit multiplier based on risk score granularity"""
        if risk_score < 0.2:
            return 0.8  # 80% of normal rate (mild throttling)
        elif risk_score < self.high_risk_threshold:
            return 0.5  # 50% of normal rate (moderate throttling)
        else:
            return 0.2  # 20% of normal rate (aggressive throttling)

    def _apply_rate_limiting(self, source_ip, pps_limit, bps_limit, risk_score):
        """Apply OpenFlow meter-based rate limiting"""
        try:
            rate_info = {
                'timestamp': datetime.now(),
                'risk_score': risk_score,
                'pps_limit': pps_limit,
                'bps_limit': bps_limit,
                'meter_ids': {}
            }
            
            for datapath in self.controller.datapaths.values():
                meter_id = self._get_available_meter_id(datapath.id)
                if meter_id is None:
                    self.logger.warning(f"⚠️ No available meter ID for switch {datapath.id}")
                    continue
                
                # Create meter rule
                meter_success = self._install_meter_rule(datapath, meter_id, pps_limit, bps_limit)
                
                if meter_success:
                    # Install flow rule with meter only if meter installation succeeded
                    self._install_rate_limited_flow(datapath, source_ip, meter_id)
                    rate_info['meter_ids'][datapath.id] = meter_id
                    
                    # Register meter usage
                    if datapath.id not in self.meter_registry:
                        self.meter_registry[datapath.id] = {}
                    self.meter_registry[datapath.id][meter_id] = source_ip
                else:
                    # Fallback: Install basic rate limiting flow without meter
                    self.logger.warning(f"⚠️ Meter installation failed for {source_ip}, using basic flow control")
                    self._install_basic_rate_limited_flow(datapath, source_ip)
            
            self.rate_limited_sources[source_ip] = rate_info
            
        except Exception as e:
            self.logger.error(f"❌ Error applying rate limiting for {source_ip}: {e}")

    def _install_meter_rule(self, datapath, meter_id, pps_limit, bps_limit):
        """Install OpenFlow meter for rate limiting with error handling"""
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # Ensure minimum rates to avoid OpenFlow errors
            min_pps = max(pps_limit, 1)  # Minimum 1 pps
            min_bps = max(bps_limit//1000, 1)  # Minimum 1 kbps
            
            # Create meter bands with proper validation
            bands = []
            
            # Packet rate band with proper burst size
            burst_pps = max(min_pps // 10, 1)  # At least 1 packet burst
            band_pps = parser.OFPMeterBandDrop(rate=min_pps, burst_size=burst_pps)
            bands.append(band_pps)
            
            # Byte rate band with proper burst size  
            burst_kbps = max(min_bps // 10, 1)  # At least 1 kbps burst
            band_bps = parser.OFPMeterBandDrop(rate=min_bps, burst_size=burst_kbps)
            bands.append(band_bps)
            
            # Delete existing meter first to avoid conflicts
            try:
                delete_meter = parser.OFPMeterMod(
                    datapath=datapath,
                    command=ofproto.OFPMC_DELETE,
                    flags=0,
                    meter_id=meter_id,
                    bands=[]
                )
                datapath.send_msg(delete_meter)
            except:
                pass  # Ignore if meter doesn't exist
            
            # Create meter modification message with proper flags
            bands = [
                        parser.OFPMeterBandDrop(rate=100, burst_size=10)  # rate in packets/s
                    ]
            meter_mod = parser.OFPMeterMod(
                        datapath=datapath,
                        command=ofproto.OFPMC_ADD,
                        flags=ofproto.OFPMF_PKTPS,
                        meter_id=meter_id,
                        bands=bands
                    )

            datapath.send_msg(meter_mod)
            self.logger.debug(f"📏 Installed meter {meter_id} on switch {datapath.id}: "
                             f"{min_pps} pps, {min_bps} kbps")
            
        except Exception as e:
            self.logger.error(f"❌ Error installing meter rule: {e}")
            # Continue without meter if installation fails
            return False
        
        return True

    def _install_rate_limited_flow(self, datapath, source_identifier, meter_id):
        """Install flow rule that applies meter for rate limiting (supports both IP and MAC)"""
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # Determine if source_identifier is IP or MAC and create appropriate match
            if self._is_ipv4_address(source_identifier):
                # IPv4 address - match by source IP
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=source_identifier)
                self.logger.debug(f"📐 Creating IPv4 rate limit rule for {source_identifier}")
            elif self._is_mac_address(source_identifier):
                # MAC address - match by source MAC
                match = parser.OFPMatch(eth_src=source_identifier)
                self.logger.debug(f"📐 Creating MAC rate limit rule for {source_identifier}")
            else:
                self.logger.error(f"❌ Invalid source identifier format: {source_identifier}")
                return
            
            # Action: Forward to output port (normal processing) with meter
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            
            # Instruction: Apply meter then actions
            inst = [
                parser.OFPInstructionMeter(meter_id),
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
            ]
            
            # Create flow rule with medium priority
            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=800,  # Higher than normal, lower than blocking
                match=match,
                instructions=inst,
                idle_timeout=300,  # 5 minute timeout
                hard_timeout=0
            )
            
            datapath.send_msg(flow_mod)
            self.logger.debug(f"📐 Installed rate-limited flow for {source_identifier} on switch {datapath.id}")
            
        except Exception as e:
            self.logger.error(f"❌ Error installing rate-limited flow: {e}")

    def _install_basic_rate_limited_flow(self, datapath, source_identifier):
        """Install basic flow rule for rate limiting without meter (fallback)"""
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # Determine if source_identifier is IP or MAC and create appropriate match
            if self._is_ipv4_address(source_identifier):
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=source_identifier)
                self.logger.debug(f"📐 Creating basic IPv4 rate limit rule for {source_identifier}")
            elif self._is_mac_address(source_identifier):
                match = parser.OFPMatch(eth_src=source_identifier)
                self.logger.debug(f"📐 Creating basic MAC rate limit rule for {source_identifier}")
            else:
                self.logger.error(f"❌ Invalid source identifier format: {source_identifier}")
                return
            
            # Basic action: Forward to normal processing but with lower priority
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            
            # Create flow rule with lower priority (basic rate limiting)
            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=750,  # Lower than metered flows
                match=match,
                instructions=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)],
                idle_timeout=60,  # Shorter timeout for basic limiting
                hard_timeout=0
            )
            
            datapath.send_msg(flow_mod)
            self.logger.debug(f"📐 Installed basic rate-limited flow for {source_identifier} on switch {datapath.id}")
            
        except Exception as e:
            self.logger.error(f"❌ Error installing basic rate-limited flow: {e}")

    def _apply_short_timeout_block(self, source_ip, timeout_duration, risk_score):
        """Apply short-duration blocking with adaptive timeout (supports both IP and MAC)"""
        try:
            block_info = {
                'timestamp': datetime.now(),
                'risk_score': risk_score,
                'timeout_duration': timeout_duration,
                'reason': f'High risk score ({risk_score:.3f})',
                'unblock_time': datetime.now() + timedelta(seconds=timeout_duration)
            }
            
            # Install blocking flows with timeout
            for datapath in self.controller.datapaths.values():
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                
                # Create appropriate match based on identifier type
                if self._is_ipv4_address(source_ip):
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=source_ip)
                elif self._is_mac_address(source_ip):
                    match = parser.OFPMatch(eth_src=source_ip)
                else:
                    self.logger.error(f"❌ Invalid source identifier for blocking: {source_ip}")
                    continue
                
                # Remove any existing flows for this source first
                try:
                    delete_flow = parser.OFPFlowMod(
                        datapath=datapath,
                        command=ofproto.OFPFC_DELETE,
                        out_port=ofproto.OFPP_ANY,
                        out_group=ofproto.OFPG_ANY,
                        match=match
                    )
                    datapath.send_msg(delete_flow)
                except:
                    pass  # Ignore if no existing flows
                
                actions = []  # No actions = drop
                
                # High priority blocking rule with timeout
                flow_mod = parser.OFPFlowMod(
                    datapath=datapath,
                    priority=1000,  # High priority for blocking
                    match=match,
                    instructions=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)],
                    idle_timeout=0,
                    hard_timeout=timeout_duration  # Automatic timeout
                )
                
                datapath.send_msg(flow_mod)
                self.logger.debug(f"🚫 Installed blocking flow for {source_ip} on switch {datapath.id}")
            
            # Update blocked sources for compatibility
            self.blocked_sources[source_ip] = block_info
            
        except Exception as e:
            self.logger.error(f"❌ Error applying short timeout block for {source_ip}: {e}")

    def _calculate_adaptive_timeout(self, source_ip, risk_score, is_honeypot_hit=False):
        """Calculate adaptive timeout duration based on risk and history"""
        # Honeypot hits result in the maximum timeout immediately
        if is_honeypot_hit:
            return self.max_blacklist_timeout
            
        # Base timeout from risk score
        base_timeout = int(self.base_blacklist_timeout * (risk_score * 2))
        
        # Escalation for repeat offenders
        if source_ip in self.blacklist:
            offense_count = self.blacklist[source_ip]['offense_count']
            escalation_factor = min(2 ** offense_count, 16)  # Cap at 16x
            base_timeout = int(base_timeout * escalation_factor)
        
        # Ensure within bounds
        return min(base_timeout, self.max_blacklist_timeout)

    def _add_to_blacklist(self, source_ip, timeout_duration, risk_score):
        """Add source to temporary blacklist with escalation"""
        current_time = datetime.now()
        
        # Remove from whitelist if present
        if source_ip in self.whitelist:
            del self.whitelist[source_ip]
            self.logger.info(f"⚫ Removed {source_ip} from whitelist due to blacklisting")
        
        if source_ip in self.blacklist:
            # Existing entry - escalate
            self.blacklist[source_ip]['offense_count'] += 1
            self.blacklist[source_ip]['last_offense'] = current_time
            self.blacklist[source_ip]['expiry'] = current_time + timedelta(seconds=timeout_duration)
            self.blacklist[source_ip]['risk_score'] = max(self.blacklist[source_ip]['risk_score'], risk_score)
        else:
            # New entry
            self.blacklist[source_ip] = {
                'first_offense': current_time,
                'last_offense': current_time,
                'offense_count': 1,
                'expiry': current_time + timedelta(seconds=timeout_duration),
                'risk_score': risk_score,
                'timeout_duration': timeout_duration
            }
        
        self.logger.warning(f"⚫ Added {source_ip} to blacklist (offense #{self.blacklist[source_ip]['offense_count']}) "
                           f"until {self.blacklist[source_ip]['expiry'].strftime('%H:%M:%S')}")

    def _add_to_whitelist(self, source_ip, reason="Consistent legitimate behavior"):
        """Add source to whitelist with trust scoring"""
        current_time = datetime.now()
        
        # Remove from blacklist if present
        if source_ip in self.blacklist:
            del self.blacklist[source_ip]
            self.logger.info(f"⚪ Removed {source_ip} from blacklist due to whitelisting")
        
        self.whitelist[source_ip] = {
            'added_time': current_time,
            'last_activity': current_time,
            'trust_score': 1.0,
            'reason': reason,
            'expiry': current_time + timedelta(seconds=self.whitelist_duration)
        }
        
        self.logger.info(f"⚪ Added {source_ip} to whitelist: {reason}")

    def _calculate_whitelist_trust(self, whitelist_entry):
        """Calculate current trust score with time-based decay"""
        current_time = datetime.now()
        hours_since_activity = (current_time - whitelist_entry['last_activity']).total_seconds() / 3600
        
        # Apply decay
        decay_amount = hours_since_activity * self.whitelist_decay_rate
        current_trust = max(0.0, whitelist_entry['trust_score'] - decay_amount)
        
        return current_trust

    def _count_recent_low_risk_flows(self, source_ip):
        """Count recent consecutive low-risk flows from source"""
        recent_records = [r for r in self.traffic_history[source_ip] 
                         if self._is_recent(r['timestamp'], minutes=10)]
        
        low_risk_count = 0
        for record in reversed(recent_records):  # Check most recent first
            if record.get('risk_score', 1.0) < self.low_risk_threshold:
                low_risk_count += 1
            else:
                break  # Stop at first non-low-risk flow
        
        return low_risk_count

    def _get_available_meter_id(self, datapath_id):
        """Get an available meter ID for the datapath"""
        if datapath_id not in self.meter_registry:
            self.meter_registry[datapath_id] = {}
        
        # Start from meter ID 100 to avoid conflicts with other applications
        for meter_id in range(100, 1000):
            if meter_id not in self.meter_registry[datapath_id]:
                return meter_id
        
        return None  # No available meter IDs

    def _remove_rate_limiting(self, source_ip):
        """Remove rate limiting for a source"""
        if source_ip not in self.rate_limited_sources:
            return
        
        try:
            rate_info = self.rate_limited_sources[source_ip]
            
            for datapath_id, meter_id in rate_info['meter_ids'].items():
                if datapath_id in self.controller.datapaths:
                    datapath = self.controller.datapaths[datapath_id]
                    
                    # Remove flow rule
                    self._remove_rate_limited_flow(datapath, source_ip)
                    
                    # Remove meter
                    self._remove_meter_rule(datapath, meter_id)
                    
                    # Unregister meter
                    if datapath_id in self.meter_registry and meter_id in self.meter_registry[datapath_id]:
                        del self.meter_registry[datapath_id][meter_id]
            
            del self.rate_limited_sources[source_ip]
            self.logger.info(f"✅ Removed rate limiting for {source_ip}")
            
        except Exception as e:
            self.logger.error(f"❌ Error removing rate limiting for {source_ip}: {e}")

    def _remove_rate_limited_flow(self, datapath, source_identifier):
        """Remove rate-limited flow rule (supports both IP and MAC)"""
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # Determine if source_identifier is IP or MAC and create appropriate match
            if self._is_ipv4_address(source_identifier):
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=source_identifier)
            elif self._is_mac_address(source_identifier):
                match = parser.OFPMatch(eth_src=source_identifier)
            else:
                self.logger.error(f"❌ Invalid source identifier for flow removal: {source_identifier}")
                return
            
            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match,
                priority=800  # Match the priority used when installing
            )
            
            datapath.send_msg(flow_mod)
            
        except Exception as e:
            self.logger.error(f"❌ Error removing rate-limited flow: {e}")

    def _remove_meter_rule(self, datapath, meter_id):
        """Remove meter rule with error handling"""
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            meter_mod = parser.OFPMeterMod(
                datapath=datapath,
                command=ofproto.OFPMC_DELETE,
                flags=0,
                meter_id=meter_id,
                bands=[]
            )
            
            datapath.send_msg(meter_mod)
            self.logger.debug(f"🗑️ Removed meter {meter_id} from switch {datapath.id}")
            
        except Exception as e:
            self.logger.debug(f"⚠️ Could not remove meter rule {meter_id}: {e}")
            # Don't treat meter removal failures as critical errors

    def _update_risk_profile(self, source_ip, risk_score, ml_confidence, flow_stats, is_honeypot_hit=False):
        """Update comprehensive risk profile for source"""
        current_time = datetime.now()
        
        # Create or update risk profile
        if source_ip not in self.risk_profiles:
            self.risk_profiles[source_ip] = {
                'first_seen': current_time,
                'risk_history': deque(maxlen=100),
                'average_risk': 0.0,
                'peak_risk': 0.0,
                'ml_confidence_history': deque(maxlen=50),
                'honeypot_hits': 0  # Initialize honeypot hit count
            }
        
        profile = self.risk_profiles[source_ip]
        
        # Increment honeypot hit count if applicable
        if is_honeypot_hit:
            profile['honeypot_hits'] += 1
        
        # DEBUG: Log all high risk events for h2 (10.0.0.2)
        if source_ip == "10.0.0.2" and risk_score >= self.high_risk_threshold:
            dest_ip = None
            if hasattr(flow_stats, 'match'):
                match_dict = flow_stats.match.to_jsondict().get('OFPMatch', {})
                dest_ip = match_dict.get('ipv4_dst')
            #self.logger.error(f"[DEBUG][H2-HIGH-RISK] h2 (10.0.0.2) assigned HIGH/CRITICAL risk: risk_score={risk_score:.3f}, ml_confidence={ml_confidence:.3f}, dest_ip={dest_ip}, flow_stats={getattr(flow_stats, 'match', None)}")

        # Update risk history
        profile['risk_history'].append({
            'timestamp': current_time,
            'risk_score': risk_score,
            'ml_confidence': ml_confidence,
            'is_honeypot_hit': is_honeypot_hit
        })
        
        profile['ml_confidence_history'].append(ml_confidence)
        
        # Update statistics
        profile['average_risk'] = sum(r['risk_score'] for r in profile['risk_history']) / len(profile['risk_history'])
        profile['peak_risk'] = max(profile['peak_risk'], risk_score)
        profile['last_seen'] = current_time
        
        # Update traffic history with risk information
        traffic_record = {
            'timestamp': current_time.isoformat(),
            'risk_score': risk_score,
            'ml_confidence': ml_confidence,
            'packet_count': getattr(flow_stats, 'packet_count', 0),
            'byte_count': getattr(flow_stats, 'byte_count', 0),
            'duration': getattr(flow_stats, 'duration_sec', 0),
            'anomalous': risk_score > self.low_risk_threshold,
            'is_honeypot_hit': is_honeypot_hit
        }
        
        self.traffic_history[source_ip].append(traffic_record)
        self._cleanup_old_records(source_ip)

    def detect_anomaly_and_mitigate(self, flow_stats, anomaly_confidence, source_ip=None):
        """
        Legacy entry point for backward compatibility
        Redirects to the new risk-based mitigation system
        
        Args:
            flow_stats: OpenFlow statistics
            anomaly_confidence: ML model confidence score
            source_ip: Source IP address (extracted if None)
        """
        self.logger.info("🔄 Legacy method called - redirecting to risk-based mitigation")
        return self.risk_based_mitigation(flow_stats, anomaly_confidence, source_ip)

    def _log_risk_action(self, source_ip, risk_score, action, flow_stats):
        """Log risk-based mitigation action"""
        log_entry = {
            'action_type': action['action'],
            'source_ip': source_ip,
            'timestamp': datetime.now().isoformat(),
            'risk_score': risk_score,
            'risk_level': action['risk_level'],
            'details': action['details'],
            'packet_count': getattr(flow_stats, 'packet_count', 0),
            'byte_count': getattr(flow_stats, 'byte_count', 0)
        }
        self._write_log_entry(log_entry)

    def _extract_source_ip(self, flow_stats):
        """Extract source IP from flow statistics"""
        try:
            if hasattr(flow_stats, 'match'):
                match_dict = flow_stats.match.to_jsondict().get('OFPMatch', {})
                source_ip = match_dict.get('ipv4_src')
                if source_ip:
                    self.logger.debug(f"✅ Extracted IPv4 source: {source_ip}")
                    return source_ip
                else:
                    self.logger.debug(f"⚠️ No IPv4 source in match: {match_dict}")
            else:
                self.logger.debug("⚠️ Flow stats has no match attribute")
            return None
        except Exception as e:
            self.logger.error(f"❌ Error extracting source IP: {e}")
            return None

    def _extract_source_mac(self, flow_stats):
        """Extract source MAC address from flow statistics as fallback"""
        try:
            if hasattr(flow_stats, 'match'):
                match_dict = flow_stats.match.to_jsondict().get('OFPMatch', {})
                source_mac = match_dict.get('eth_src')
                if source_mac:
                    self.logger.debug(f"✅ Extracted MAC source: {source_mac}")
                    return source_mac
                else:
                    self.logger.debug(f"⚠️ No MAC source in match: {match_dict}")
            else:
                self.logger.debug("⚠️ Flow stats has no match attribute")
            return None
        except Exception as e:
            self.logger.debug(f"❌ Error extracting MAC: {e}")
            return None

    def _is_ipv4_address(self, address):
        """Check if address is a valid IPv4 address"""
        try:
            ipaddress.IPv4Address(address)
            return True
        except:
            return False

    def _is_mac_address(self, address):
        """Check if address is a valid MAC address"""
        try:
            # MAC address pattern: XX:XX:XX:XX:XX:XX
            mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
            return bool(re.match(mac_pattern, address))
        except:
            return False

    def _log_failed_mitigation(self, flow_stats, ml_confidence, reason):
        """Log failed mitigation attempts for debugging"""
        try:
            log_entry = {
                'action_type': 'FAILED_MITIGATION',
                'timestamp': datetime.now().isoformat(),
                'ml_confidence': ml_confidence,
                'reason': reason,
                'flow_details': {
                    'packet_count': getattr(flow_stats, 'packet_count', 0),
                    'byte_count': getattr(flow_stats, 'byte_count', 0),
                    'duration_sec': getattr(flow_stats, 'duration_sec', 0)
                }
            }
            self._write_log_entry(log_entry)
        except Exception as e:
            self.logger.error(f"Error logging failed mitigation: {e}")

    def _record_anomaly(self, source_ip, flow_stats, confidence):
        """Record anomalous behavior for analysis"""
        timestamp = datetime.now()
        
        # Increment anomaly counter
        self.anomaly_counts[source_ip] += 1
        
        # Record traffic pattern
        traffic_record = {
            'timestamp': timestamp.isoformat(),
            'confidence': confidence,
            'packet_count': getattr(flow_stats, 'packet_count', 0),
            'byte_count': getattr(flow_stats, 'byte_count', 0),
            'duration': getattr(flow_stats, 'duration_sec', 0),
            'anomalous': True
        }
        
        # Maintain sliding window of traffic history
        self.traffic_history[source_ip].append(traffic_record)
        self._cleanup_old_records(source_ip)

    def _should_block_source(self, source_ip, confidence):
        """
        Intelligent decision making for blocking
        Considers multiple factors: confidence, frequency, pattern analysis
        """
        # High confidence immediate block
        if confidence > 0.9:
            self.logger.info(f"🚨 High confidence anomaly ({confidence:.3f}) - Immediate block: {source_ip}")
            return True
        
        # Check if already blocked
        if source_ip in self.blocked_sources:
            return False
        
        # Frequency-based blocking
        recent_anomalies = self._count_recent_anomalies(source_ip, minutes=5)
        if recent_anomalies >= 3:
            self.logger.info(f"🚨 Frequent anomalies ({recent_anomalies}) - Block: {source_ip}")
            return True
            
        # Pattern-based blocking
        if self._is_attack_pattern(source_ip):
            self.logger.info(f"🚨 Attack pattern detected - Block: {source_ip}")
            return True
            
        # Confidence threshold
        if confidence > self.threat_threshold:
            self.logger.info(f"🚨 Confidence threshold exceeded ({confidence:.3f}) - Block: {source_ip}")
            return True
            
        return False

    def _block_source(self, source_ip, confidence, flow_stats):
        """
        Implement source-based blocking strategy
        """
        try:
            block_info = {
                'timestamp': datetime.now(),
                'confidence': confidence,
                'reason': self._determine_block_reason(source_ip, confidence),
                'duration': self._calculate_block_duration(source_ip, confidence),
                'unblock_time': datetime.now() + timedelta(seconds=self._calculate_block_duration(source_ip, confidence)),
                'flow_stats': self._serialize_flow_stats(flow_stats)
            }
            
            self.blocked_sources[source_ip] = block_info
            
            # Install blocking flows in all switches
            self._install_blocking_flows(source_ip)
            
            # Log the blocking action
            self._log_blocking_action(source_ip, block_info)
            
            self.logger.warning(f"🚫 BLOCKED SOURCE: {source_ip} for {block_info['duration']}s - Reason: {block_info['reason']}")
            
        except Exception as e:
            self.logger.error(f"❌ Error blocking source {source_ip}: {e}")

    def _install_blocking_flows(self, source_ip):
        """
        Install blocking flows in all connected switches (supports both IP and MAC)
        """
        try:
            for datapath in self.controller.datapaths.values():
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                
                # Create appropriate match based on identifier type
                if self._is_ipv4_address(source_ip):
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=source_ip)
                    self.logger.info(f"🚫 Installing IPv4 blocking flow for {source_ip} on switch {datapath.id}")
                elif self._is_mac_address(source_ip):
                    match = parser.OFPMatch(eth_src=source_ip)
                    self.logger.info(f"🚫 Installing MAC blocking flow for {source_ip} on switch {datapath.id}")
                else:
                    self.logger.error(f"❌ Invalid source identifier for blocking: {source_ip}")
                    continue
                
                # Action: Drop packets (no actions = drop)
                actions = []
                
                # High priority blocking rule
                mod = parser.OFPFlowMod(
                    datapath=datapath,
                    priority=1000,  # High priority
                    match=match,
                    instructions=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)],
                    idle_timeout=0,  # Permanent until manually removed
                    hard_timeout=int(self.blocked_sources[source_ip]['duration'])
                )
                
                datapath.send_msg(mod)
                
        except Exception as e:
            self.logger.error(f"❌ Error installing blocking flows for {source_ip}: {e}")

    def _determine_block_reason(self, source_ip, confidence):
        """Determine the reason for blocking"""
        recent_anomalies = self._count_recent_anomalies(source_ip, minutes=5)
        
        if confidence > 0.9:
            return "High confidence anomaly"
        elif recent_anomalies >= 3:
            return f"Frequent anomalies ({recent_anomalies} in 5 min)"
        elif self._is_attack_pattern(source_ip):
            return "Attack pattern detected"
        else:
            return f"Confidence threshold exceeded ({confidence:.3f})"

    def _calculate_block_duration(self, source_ip, confidence):
        """
        Calculate adaptive block duration based on threat level and history
        """
        base_duration = self.block_duration
        
        # Increase duration for repeat offenders
        previous_blocks = sum(1 for record in self.traffic_history[source_ip] 
                            if record.get('blocked', False))
        
        # Adjust based on confidence
        confidence_multiplier = min(confidence * 2, 2.0)
        
        # Adjust based on frequency
        frequency_multiplier = min(self.anomaly_counts[source_ip] * 0.1, 1.5)
        
        duration = int(base_duration * confidence_multiplier * (1 + frequency_multiplier))
        return min(duration, 3600)  # Max 1 hour

    def _is_attack_pattern(self, source_ip):
        """
        Analyze traffic patterns to identify attack signatures
        """
        recent_records = [r for r in self.traffic_history[source_ip] 
                         if self._is_recent(r['timestamp'], minutes=2)]
        
        if len(recent_records) < 3:
            return False
            
        # DDoS pattern: High frequency, small packets
        avg_packets = sum(r['packet_count'] for r in recent_records) / len(recent_records)
        avg_duration = sum(r['duration'] for r in recent_records) / len(recent_records)
        
        if len(recent_records) > 10 and avg_duration < 0.1:  # Very short flows
            return True
            
        # Port scanning pattern: Many different destination ports
        if len(recent_records) > 20 and avg_packets < 5:  # Many small flows
            return True
            
        return False

    def _count_recent_anomalies(self, source_ip, minutes=5):
        """Count anomalies from a source in recent time window"""
        recent_time = datetime.now() - timedelta(minutes=minutes)
        return sum(1 for record in self.traffic_history[source_ip]
                  if self._parse_timestamp(record['timestamp']) > recent_time and record['anomalous'])

    def _background_monitor(self):
        """
        Continuous security monitoring and adaptive management background service.
        
        Runs as a daemon thread to provide continuous system maintenance, security
        policy enforcement, and adaptive learning capabilities. This service ensures
        optimal system performance through proactive cleanup, trust score management,
        and automatic policy adjustments based on observed network behavior patterns.
        
        Background Monitoring Functions:
        - Automatic unblocking based on behavior improvement and timeout expiry
        - Expired security policy cleanup (blacklist/whitelist maintenance)
        - Dynamic trust score updates with time-based decay mechanisms
        - Historical data cleanup to prevent memory exhaustion
        - Rate limiting effectiveness monitoring and automatic adjustment
        - System health monitoring and performance optimization
        
        Monitoring Cycle: 30-second intervals for responsive security management
        Error Handling: Comprehensive exception handling to prevent service disruption
        Thread Safety: Designed for safe concurrent operation with main controller
        """
        while self.monitoring_active:
            try:
                # Evaluate automatic unblocking conditions for expired timeouts and behavior improvement
                self._check_unblock_conditions()
                
                # Maintain security policy hygiene through expired entry cleanup
                self._cleanup_expired_entries()
                
                # Update dynamic trust scoring with time-based decay mechanisms
                self._update_whitelist_trust_scores()
                
                # Prevent memory exhaustion through historical data cleanup
                self._cleanup_old_data()
                
                # Optimize security effectiveness through rate limiting performance analysis
                self._monitor_rate_limiting_effectiveness()
                
                # 30-second monitoring cycle balances responsiveness with system overhead
                time.sleep(30)
                
            except Exception as e:
                self.logger.error(f"❌ Background monitor error: {e}")
                # Continue monitoring despite errors to maintain security service availability

    def _cleanup_expired_entries(self):
        """Clean up expired blacklist and whitelist entries"""
        current_time = datetime.now()
        
        # Clean up expired blacklist entries
        expired_blacklist = [ip for ip, entry in self.blacklist.items() 
                           if current_time >= entry['expiry']]
        for ip in expired_blacklist:
            del self.blacklist[ip]
            self.logger.info(f"⚫ Removed expired blacklist entry: {ip}")
        
        # Clean up expired whitelist entries
        expired_whitelist = [ip for ip, entry in self.whitelist.items() 
                           if current_time >= entry['expiry'] or self._calculate_whitelist_trust(entry) < 0.1]
        for ip in expired_whitelist:
            del self.whitelist[ip]
            self.logger.info(f"⚪ Removed expired whitelist entry: {ip}")

    def _update_whitelist_trust_scores(self):
        """Update trust scores for whitelist entries"""
        current_time = datetime.now()
        
        for ip, entry in self.whitelist.items():
            old_trust = entry['trust_score']
            new_trust = self._calculate_whitelist_trust(entry)
            
            if new_trust != old_trust:
                entry['trust_score'] = new_trust
                if new_trust < 0.5:
                    self.logger.info(f"⚪ Trust score for {ip} decreased to {new_trust:.2f}")

    def _monitor_rate_limiting_effectiveness(self):
        """Monitor and adjust rate limiting effectiveness"""
        for source_ip, rate_info in list(self.rate_limited_sources.items()):
            # Check if rate limiting should be removed (low risk sustained)
            if self._should_remove_rate_limiting(source_ip):
                self._remove_rate_limiting(source_ip)
                self.logger.info(f"📈 Removed rate limiting for {source_ip} - sustained low risk")

    def _should_remove_rate_limiting(self, source_ip):
        """Determine if rate limiting should be removed"""
        if source_ip not in self.rate_limited_sources:
            return False
        
        # Check recent risk scores
        recent_records = [r for r in self.traffic_history[source_ip] 
                         if self._is_recent(r['timestamp'], minutes=5)]
        
        if len(recent_records) < 5:
            return False
        
        # If all recent records are low risk, remove rate limiting
        all_low_risk = all(r.get('risk_score', 1.0) < self.low_risk_threshold 
                          for r in recent_records[-5:])
        
        return all_low_risk

    def _check_unblock_conditions(self):
        """
        Check if any blocked sources should be unblocked
        """
        current_time = datetime.now()
        to_unblock = []
        
        for source_ip, block_info in self.blocked_sources.items():
            # Time-based unblocking
            if current_time >= block_info['unblock_time']:
                unblock_reason = "Time-based unblock"
                to_unblock.append((source_ip, unblock_reason))
                continue
                
            # Behavior-based unblocking (if source shows legitimate behavior)
            if self._should_unblock_early(source_ip):
                unblock_reason = "Legitimate behavior detected"
                to_unblock.append((source_ip, unblock_reason))
        
        # Perform unblocking
        for source_ip, reason in to_unblock:
            self._unblock_source(source_ip, reason)

    def _should_unblock_early(self, source_ip):
        """
        Determine if source should be unblocked early based on behavior analysis
        Currently uses time-based approach, can be enhanced with ML
        """
        # For now, implement conservative early unblocking
        # This can be enhanced with additional ML models or behavior analysis
        return False

    def _unblock_source(self, source_ip, reason="Manual unblock"):
        """
        Remove blocking flows and unblock source
        """
        try:
            if source_ip not in self.blocked_sources:
                return
                
            # Remove blocking flows from all switches
            self._remove_blocking_flows(source_ip)
            
            # Log unblocking action
            block_info = self.blocked_sources[source_ip]
            unblock_info = {
                'source_ip': source_ip,
                'unblock_time': datetime.now().isoformat(),
                'reason': reason,
                'blocked_duration': (datetime.now() - block_info['timestamp']).total_seconds(),
                'original_block_reason': block_info['reason']
            }
            
            self._log_unblocking_action(source_ip, unblock_info)
            
            # Remove from blocked sources
            del self.blocked_sources[source_ip]
            
            self.logger.info(f"✅ UNBLOCKED SOURCE: {source_ip} - Reason: {reason}")
            
        except Exception as e:
            self.logger.error(f"❌ Error unblocking source {source_ip}: {e}")

    def _remove_blocking_flows(self, source_ip):
        """
        Remove blocking flows from all switches (supports both IP and MAC)
        """
        try:
            for datapath in self.controller.datapaths.values():
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                
                # Create appropriate match based on identifier type
                if self._is_ipv4_address(source_ip):
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=source_ip)
                elif self._is_mac_address(source_ip):
                    match = parser.OFPMatch(eth_src=source_ip)
                else:
                    self.logger.error(f"❌ Invalid source identifier for unblocking: {source_ip}")
                    continue
                
                # Delete the flow
                mod = parser.OFPFlowMod(
                    datapath=datapath,
                    command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match
                )
                
                datapath.send_msg(mod)
                self.logger.info(f"✅ Removed blocking flow for {source_ip} from switch {datapath.id}")
                
        except Exception as e:
            self.logger.error(f"❌ Error removing blocking flows for {source_ip}: {e}")

    def manual_unblock(self, source_ip):
        """
        Manually unblock a source (for admin intervention)
        """
        self._unblock_source(source_ip, "Manual admin unblock")

    def get_blocked_sources(self):
        """
        Get list of currently blocked sources
        """
        return {
            ip: {
                'blocked_since': info['timestamp'].isoformat(),
                'reason': info['reason'],
                'unblock_time': info['unblock_time'].isoformat(),
                'confidence': info['confidence']
            }
            for ip, info in self.blocked_sources.items()
        }

    def get_risk_analytics(self):
        """
        Generate comprehensive security analytics dashboard for operational intelligence.
        
        Provides real-time security analytics aggregating system status, threat intelligence,
        mitigation effectiveness, and performance metrics for Security Operations Center (SOC)
        monitoring and executive reporting. Includes predictive indicators and trend analysis
        for proactive security management and resource allocation planning.
        
        Analytics Components:
        - System Status: Current active policies and resource utilization
        - Risk Distribution: Threat level categorization across monitored sources  
        - Mitigation Actions: Recent security response activity and effectiveness
        - Top Risk Sources: Highest threat actors requiring immediate attention
        - Policy Summaries: Blacklist/whitelist status with trend indicators
        - Performance Metrics: False positive estimation and system efficiency
        
        Use Cases:
        - SOC dashboard real-time threat monitoring
        - Executive security posture reporting
        - Compliance audit documentation
        - Performance optimization analysis
        - Capacity planning and resource allocation
        
        Returns:
            dict: Comprehensive analytics package with system status and threat intelligence
        """
        current_time = datetime.now()
        
        # Aggregate comprehensive security analytics for operational intelligence
        analytics = {
            'system_status': {
                'active_blacklist_entries': len(self.blacklist),
                'active_whitelist_entries': len(self.whitelist), 
                'rate_limited_sources': len(self.rate_limited_sources),
                'blocked_sources': len(self.blocked_sources),
                'total_monitored_sources': len(self.risk_profiles),
                'total_honeypot_hits': sum(self.honeypot_hits.values()),
                'monitoring_uptime': self.monitoring_active,
                'timestamp': current_time.isoformat()
            },
            'threat_intelligence': {
                'risk_distribution': self._calculate_risk_distribution(),
                'top_risk_sources': self._get_top_risk_sources(),
                'honeypot_threat_indicators': dict(self.honeypot_hits)
            },
            'mitigation_effectiveness': {
                'recent_actions': self._get_recent_mitigation_actions(),
                'blacklist_summary': self._get_blacklist_summary(),
                'whitelist_summary': self._get_whitelist_summary(),
                'false_positive_metrics': self._estimate_false_positive_rate()
            }
        }
        
        return analytics

    def _calculate_risk_distribution(self):
        """Calculate current risk score distribution"""
        if not self.risk_profiles:
            return {'low': 0, 'medium': 0, 'high': 0}
        
        distribution = {'low': 0, 'medium': 0, 'high': 0}
        
        for ip, profile in self.risk_profiles.items():
            if profile['risk_history']:
                current_risk = profile['risk_history'][-1]['risk_score']
                if current_risk < self.low_risk_threshold:
                    distribution['low'] += 1
                elif current_risk < self.medium_risk_threshold:
                    distribution['medium'] += 1
                else:
                    distribution['high'] += 1
        
        return distribution

    def _get_recent_mitigation_actions(self, hours=1):
        """Get recent mitigation actions from log"""
        # This would typically read from the log file
        # For now, return a summary of current active mitigations
        return {
            'rate_limiting_applied': len(self.rate_limited_sources),
            'short_blocks_applied': len([ip for ip in self.blocked_sources 
                                       if 'risk_score' in self.blocked_sources[ip]]),
            'sources_whitelisted': len([ip for ip, entry in self.whitelist.items() 
                                      if (datetime.now() - entry['added_time']).total_seconds() < hours * 3600])
        }

    def _get_top_risk_sources(self, limit=10):
        """Get top risk sources by current risk score"""
        risk_scores = []
        
        for ip, profile in self.risk_profiles.items():
            if profile['risk_history']:
                current_risk = profile['risk_history'][-1]['risk_score']
                risk_scores.append({
                    'source_ip': ip,
                    'current_risk': current_risk,
                    'average_risk': profile['average_risk'],
                    'peak_risk': profile['peak_risk'],
                    'first_seen': profile['first_seen'].isoformat(),
                    'status': self._get_source_status(ip),
                    'honeypot_hits': self.honeypot_hits.get(ip, 0)
                })
        
        # Sort by honeypot hits first, then by current risk score
        risk_scores.sort(key=lambda x: (x['honeypot_hits'], x['current_risk']), reverse=True)
        return risk_scores[:limit]

    def _get_source_status(self, source_ip):
        """Get current status of a source"""
        if source_ip in self.blocked_sources:
            return 'BLOCKED'
        elif source_ip in self.rate_limited_sources:
            return 'RATE_LIMITED'
        elif source_ip in self.blacklist:
            return 'BLACKLISTED'
        elif source_ip in self.whitelist:
            return 'WHITELISTED'
        else:
            return 'MONITORED'

    def _get_blacklist_summary(self):
        """Get blacklist summary statistics"""
        if not self.blacklist:
            return {}
        
        offense_counts = [entry['offense_count'] for entry in self.blacklist.values()]
        
        return {
            'total_entries': len(self.blacklist),
            'average_offense_count': sum(offense_counts) / len(offense_counts),
            'max_offense_count': max(offense_counts),
            'repeat_offenders': len([c for c in offense_counts if c > 1])
        }

    def _get_whitelist_summary(self):
        """Get whitelist summary statistics"""
        if not self.whitelist:
            return {}
        
        trust_scores = [self._calculate_whitelist_trust(entry) for entry in self.whitelist.values()]
        
        return {
            'total_entries': len(self.whitelist),
            'average_trust_score': sum(trust_scores) / len(trust_scores),
            'high_trust_sources': len([t for t in trust_scores if t > 0.8]),
            'decaying_trust_sources': len([t for t in trust_scores if t < 0.5])
        }

    def _estimate_false_positive_rate(self):
        """Estimate false positive rate based on whitelist recoveries"""
        # This is a simplified estimation
        total_mitigated = len(self.blocked_sources) + len(self.rate_limited_sources) + len(self.blacklist)
        recovered_to_whitelist = len(self.whitelist)
        
        if total_mitigated == 0:
            return {'estimated_fp_rate': 0.0, 'confidence': 'low'}
        
        fp_rate = recovered_to_whitelist / (total_mitigated + recovered_to_whitelist)
        
        return {
            'estimated_fp_rate': fp_rate,
            'total_mitigated': total_mitigated,
            'recovered_sources': recovered_to_whitelist,
            'confidence': 'medium' if total_mitigated > 10 else 'low'
        }

    def get_source_detailed_analysis(self, source_ip):
        """
        Get detailed analysis for a specific source
        """
        if source_ip not in self.risk_profiles:
            return None
        
        profile = self.risk_profiles[source_ip]
        
        analysis = {
            'source_ip': source_ip,
            'current_status': self._get_source_status(source_ip),
            'risk_profile': {
                'current_risk': profile['risk_history'][-1]['risk_score'] if profile['risk_history'] else 0.0,
                'average_risk': profile['average_risk'],
                'peak_risk': profile['peak_risk'],
                'risk_trend': self._calculate_risk_trend(source_ip)
            },
            'traffic_statistics': self._get_traffic_statistics(source_ip),
            'mitigation_history': self._get_mitigation_history(source_ip),
            'reputation': {
                'blacklist_status': self.blacklist.get(source_ip, None),
                'whitelist_status': self.whitelist.get(source_ip, None),
                'trust_score': self._calculate_whitelist_trust(self.whitelist[source_ip]) if source_ip in self.whitelist else 0.0
            },
            'recommendations': self._generate_source_recommendations(source_ip)
        }
        
        return analysis

    def _handle_honeypot_hit(self, source_ip, dest_ip, flow_stats):
        """
        Handle honeypot access attempts with immediate maximum security response.
        
        Centralized honeypot hit processing that applies maximum security penalties
        for sources attempting to access honeypot IP addresses. This indicates
        malicious reconnaissance and triggers immediate blocking with maximum timeout.
        
        Args:
            source_ip (str): Source IP attempting honeypot access
            dest_ip (str): Honeypot IP being accessed
            flow_stats: Flow statistics for incident documentation
            
        Returns:
            dict: Honeypot hit response with immediate blocking action
        """
        # Increment honeypot hit counter for threat intelligence
        self.honeypot_hits[source_ip] = self.honeypot_hits.get(source_ip, 0) + 1
        
        self.logger.warning(f"🍯 HONEYPOT HIT DETECTED: {source_ip} → {dest_ip} "
                           f"(total hits: {self.honeypot_hits[source_ip]}) - APPLYING MAX PENALTY")
        
        # Apply immediate maximum security response (bypasses normal risk assessment)
        risk_score = 1.0  # Maximum risk for honeypot hits
        
        # Update risk profile with honeypot hit flag
        self._update_risk_profile(source_ip, risk_score, 1.0, flow_stats, is_honeypot_hit=True)
        
        # Apply maximum penalty blocking
        mitigation_action = self._handle_high_risk(source_ip, risk_score, flow_stats, is_honeypot_hit=True)
        
        # Log the security action
        self._log_risk_action(source_ip, risk_score, mitigation_action, flow_stats)
        
        # Return structured response for evaluate_flow_security
        return {
            'action': 'HONEYPOT_HIT',
            'priority': 'CRITICAL',
            'immediate_block': True,
            'reason': f'Honeypot access attempt to {dest_ip}',
            'honeypot_hits': self.honeypot_hits[source_ip],
            'mitigation_applied': mitigation_action
        }

    def _calculate_risk_trend(self, source_ip):
        """Calculate risk trend for a source"""
        if source_ip not in self.risk_profiles:
            return 'unknown'
        
        risk_history = self.risk_profiles[source_ip]['risk_history']
        if len(risk_history) < 3:
            return 'insufficient_data'
        
        # Calculate trend over last few measurements
        recent_risks = [r['risk_score'] for r in risk_history[-5:]]
        
        if len(recent_risks) >= 3:
            trend_slope = (recent_risks[-1] - recent_risks[0]) / len(recent_risks)
            
            if trend_slope > 0.1:
                return 'increasing'
            elif trend_slope < -0.1:
                return 'decreasing'
            else:
                return 'stable'
        
        return 'stable'

    def _get_traffic_statistics(self, source_ip):
        """Get traffic statistics for a source"""
        records = list(self.traffic_history[source_ip])
        
        if not records:
            return {}
        
        total_packets = sum(r.get('packet_count', 0) for r in records)
        total_bytes = sum(r.get('byte_count', 0) for r in records)
        anomalous_flows = sum(1 for r in records if r.get('anomalous', False))
        
        return {
            'total_flows': len(records),
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'anomalous_flows': anomalous_flows,
            'anomaly_rate': anomalous_flows / len(records) if records else 0,
            'average_packet_count': total_packets / len(records) if records else 0,
            'first_seen': records[0]['timestamp'] if records else None,
            'last_seen': records[-1]['timestamp'] if records else None
        }

    def _get_mitigation_history(self, source_ip):
        """Get mitigation history for a source"""
        history = {
            'times_blocked': 0,
            'times_rate_limited': 0,
            'times_blacklisted': 0,
            'times_whitelisted': 0,
            'current_mitigation': None
        }
        
        # Check current state
        if source_ip in self.blocked_sources:
            history['current_mitigation'] = 'blocked'
        elif source_ip in self.rate_limited_sources:
            history['current_mitigation'] = 'rate_limited'
        elif source_ip in self.blacklist:
            history['current_mitigation'] = 'blacklisted'
        elif source_ip in self.whitelist:
            history['current_mitigation'] = 'whitelisted'
        
        # Count historical events (simplified - would need log analysis for full history)
        if source_ip in self.blacklist:
            history['times_blacklisted'] = self.blacklist[source_ip]['offense_count']
        
        return history

    def _generate_source_recommendations(self, source_ip):
        """Generate recommendations for handling a specific source"""
        recommendations = []
        
        if source_ip not in self.risk_profiles:
            return ['Monitor for more data']
        
        profile = self.risk_profiles[source_ip]
        current_risk = profile['risk_history'][-1]['risk_score'] if profile['risk_history'] else 0.0
        
        # Generate contextual recommendations
        if current_risk > 0.8:
            recommendations.append('High risk - consider immediate blocking')
        elif current_risk > 0.4:
            recommendations.append('Medium risk - continue rate limiting')
        elif current_risk < 0.1 and source_ip in self.rate_limited_sources:
            recommendations.append('Low risk - consider removing rate limits')
        
        if source_ip in self.blacklist and self.blacklist[source_ip]['offense_count'] > 3:
            recommendations.append('Repeat offender - consider extended blocking')
        
        if self._calculate_risk_trend(source_ip) == 'decreasing':
            recommendations.append('Risk trend improving - monitor for whitelist consideration')
        
        if not recommendations:
            recommendations.append('Continue monitoring with current settings')
        
        return recommendations

    # Legacy compatibility methods
    def get_blocked_sources(self):
        """Legacy method - returns both blocked and rate-limited sources"""
        result = {}
        
        # Add traditionally blocked sources
        for ip, info in self.blocked_sources.items():
            result[ip] = {
                'blocked_since': info['timestamp'].isoformat(),
                'reason': info.get('reason', 'High risk'),
                'unblock_time': info['unblock_time'].isoformat(),
                'confidence': info.get('risk_score', info.get('confidence', 0.0)),
                'mitigation_type': 'blocked'
            }
        
        # Add rate-limited sources
        for ip, info in self.rate_limited_sources.items():
            result[ip] = {
                'blocked_since': info['timestamp'].isoformat(),
                'reason': f"Rate limited (risk: {info['risk_score']:.3f})",
                'unblock_time': 'dynamic',
                'confidence': info['risk_score'],
                'mitigation_type': 'rate_limited',
                'pps_limit': info['pps_limit'],
                'bps_limit': info['bps_limit']
            }
        
        return result

    def get_threat_analysis(self, source_ip):
        """Enhanced threat analysis with risk-based metrics"""
        if source_ip not in self.traffic_history:
            return None
        
        # Get detailed analysis
        detailed = self.get_source_detailed_analysis(source_ip)
        if not detailed:
            return None
        
        # Convert to legacy format for compatibility
        records = list(self.traffic_history[source_ip])
        recent_anomalies = sum(1 for r in records 
                             if self._is_recent(r['timestamp'], minutes=10) and r.get('anomalous', False))
        
        return {
            'source_ip': source_ip,
            'total_records': len(records),
            'anomaly_count': sum(1 for r in records if r.get('anomalous', False)),
            'recent_anomalies': recent_anomalies,
            'is_blocked': source_ip in self.blocked_sources,
            'is_rate_limited': source_ip in self.rate_limited_sources,
            'attack_pattern_detected': self._is_attack_pattern(source_ip),
            'threat_level': self._calculate_threat_level_from_risk(source_ip),
            'current_risk_score': detailed['risk_profile']['current_risk'],
            'risk_trend': detailed['risk_profile']['risk_trend']
        }

    def _calculate_threat_level_from_risk(self, source_ip):
        """Calculate threat level from risk score"""
        if source_ip not in self.risk_profiles or not self.risk_profiles[source_ip]['risk_history']:
            return "UNKNOWN"
        
        current_risk = self.risk_profiles[source_ip]['risk_history'][-1]['risk_score']
        
        if current_risk >= 0.7:
            return "CRITICAL"
        elif current_risk >= self.medium_risk_threshold:
            return "HIGH"
        elif current_risk >= self.low_risk_threshold:
            return "MEDIUM"
        else:
            return "LOW"

    def _calculate_threat_level(self, source_ip):
        """Calculate overall threat level for a source"""
        anomaly_ratio = self.anomaly_counts[source_ip] / max(len(self.traffic_history[source_ip]), 1)
        recent_anomalies = self._count_recent_anomalies(source_ip, minutes=5)
        
        if recent_anomalies > 5 or anomaly_ratio > 0.8:
            return "HIGH"
        elif recent_anomalies > 2 or anomaly_ratio > 0.5:
            return "MEDIUM"
        elif recent_anomalies > 0 or anomaly_ratio > 0.2:
            return "LOW"
        else:
            return "MINIMAL"

    # Utility methods
    def _log_blocking_action(self, source_ip, block_info):
        """Log blocking action to file"""
        log_entry = {
            'action': 'BLOCK',
            'source_ip': source_ip,
            'timestamp': block_info['timestamp'].isoformat(),
            'confidence': block_info['confidence'],
            'reason': block_info['reason'],
            'duration': block_info['duration']
        }
        self._write_log_entry(log_entry)

    def _log_unblocking_action(self, source_ip, unblock_info):
        """Log unblocking action to file"""
        log_entry = {
            'action': 'UNBLOCK',
            **unblock_info
        }
        self._write_log_entry(log_entry)

    def _log_suspicious_activity(self, source_ip, confidence, flow_stats):
        """Log suspicious but not blocked activity"""
        log_entry = {
            'action': 'SUSPICIOUS',
            'source_ip': source_ip,
            'timestamp': datetime.now().isoformat(),
            'confidence': confidence,
            'packet_count': getattr(flow_stats, 'packet_count', 0),
            'byte_count': getattr(flow_stats, 'byte_count', 0)
        }
        self._write_log_entry(log_entry)

    def _serialize_flow_stats(self, flow_stats):
        """Serialize flow statistics for logging"""
        return {
            'packet_count': getattr(flow_stats, 'packet_count', 0),
            'byte_count': getattr(flow_stats, 'byte_count', 0),
            'duration_sec': getattr(flow_stats, 'duration_sec', 0)
        }

    def _cleanup_old_records(self, source_ip):
        """Clean up old traffic records outside analysis window"""
        cutoff_time = datetime.now() - timedelta(seconds=self.analysis_window * 2)
        self.traffic_history[source_ip] = deque([
            record for record in self.traffic_history[source_ip]
            if self._parse_timestamp(record['timestamp']) > cutoff_time
        ])

    def _cleanup_old_data(self):
        """Periodic cleanup of old data"""
        for source_ip in list(self.traffic_history.keys()):
            self._cleanup_old_records(source_ip)

    def _is_recent(self, timestamp_str, minutes=5):
        """Check if timestamp is within recent time window"""
        timestamp = self._parse_timestamp(timestamp_str)
        return timestamp > (datetime.now() - timedelta(minutes=minutes))

    def _parse_timestamp(self, timestamp_str):
        """Parse ISO timestamp string"""
        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00').replace('+00:00', ''))

    def _write_log_entry(self, log_entry):
        """Write log entry to JSON log file"""
        try:
            with open('risk_mitigation_actions.json', 'a') as f:
                json.dump(log_entry, f)
                f.write('\n')
        except Exception as e:
            self.logger.error(f"❌ Error writing log entry: {e}")

    def shutdown(self):
        """
        Graceful shutdown with comprehensive cleanup of all active security mitigations.
        
        Performs orderly system shutdown ensuring all active security policies are
        properly removed from network infrastructure to prevent orphaned flow rules
        and maintain network connectivity. Generates final security audit logs for
        compliance and operational handover documentation.
        
        Shutdown Procedure:
        1. Stop background monitoring thread gracefully
        2. Remove all active rate limiting policies and OpenFlow meters
        3. Clear all blocking flow rules from network switches
        4. Clean up OpenFlow meter allocations to prevent resource leaks
        5. Generate comprehensive shutdown audit log with final statistics
        6. Ensure complete system state cleanup for clean restart capability
        
        Error Handling: Continues cleanup despite individual component failures
        Audit Compliance: Logs final system state for security audit trails
        Resource Management: Prevents OpenFlow resource leaks in SDN infrastructure
        """
        self.logger.info("🛡️ Initiating Risk-Based Mitigation Manager shutdown sequence...")
        
        # Gracefully terminate background monitoring service
        self.monitoring_active = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)  # 5-second timeout for graceful shutdown
        
        # Comprehensive cleanup of all active security mitigations
        try:
            # Remove all OpenFlow-based rate limiting policies and meters
            for source_ip in list(self.rate_limited_sources.keys()):
                self._remove_rate_limiting(source_ip)
            self.logger.info(f"✅ Cleaned up {len(self.rate_limited_sources)} rate limiting policies")
            
            # Remove all blocking flow rules from network infrastructure  
            for source_ip in list(self.blocked_sources.keys()):
                self._remove_blocking_flows(source_ip)
            self.logger.info(f"✅ Cleaned up {len(self.blocked_sources)} blocking policies")
            
            # Clear all OpenFlow meter allocations to prevent resource leaks
            meter_count = 0
            for datapath_id, meters in self.meter_registry.items():
                if datapath_id in self.controller.datapaths:
                    datapath = self.controller.datapaths[datapath_id]
                    for meter_id in meters:
                        self._remove_meter_rule(datapath, meter_id)
                        meter_count += 1
            self.logger.info(f"✅ Cleaned up {meter_count} OpenFlow meters")
        
        except Exception as e:
            self.logger.error(f"❌ Cleanup error (continuing): {e}")
        
        # Generate final security audit log for compliance and operational handover
        final_stats = {
            'shutdown_time': datetime.now().isoformat(),
            'total_sources_monitored': len(self.risk_profiles),
            'final_blacklist_count': len(self.blacklist),
            'final_whitelist_count': len(self.whitelist),
            'total_mitigations_applied': len(self.blocked_sources) + len(self.rate_limited_sources),
            'honeypot_hits_total': sum(self.honeypot_hits.values()),
            'system_uptime_summary': 'Graceful shutdown completed'
        }
        
        self._write_log_entry({'action': 'SYSTEM_SHUTDOWN', **final_stats})
        self.logger.info("🛡️ Risk-Based Mitigation Manager shutdown sequence completed successfully")

    # Manual override methods for admin control
    def manual_whitelist(self, source_ip, reason="Manual admin whitelist"):
        """
        Administrative function to manually add trusted sources to security whitelist.
        
        Provides security operators with the ability to override automated security
        decisions and immediately classify sources as trusted. Automatically removes
        any existing security restrictions and prevents future automated mitigations
        against the specified source until whitelist expiry or manual removal.
        
        Args:
            source_ip (str): Source IP address to add to trusted whitelist
            reason (str): Administrative justification for whitelist inclusion
        """
        self._add_to_whitelist(source_ip, reason)
        
        # Remove any existing automated security restrictions
        if source_ip in self.rate_limited_sources:
            self._remove_rate_limiting(source_ip)
        if source_ip in self.blocked_sources:
            self._unblock_source(source_ip, "Administrative whitelist override")
            
        self.logger.info(f"🔧 ADMIN WHITELIST: {source_ip} - {reason}")

    def manual_blacklist(self, source_ip, duration=3600, reason="Manual admin blacklist"):
        """
        Administrative function to immediately blacklist suspected threat sources.
        
        Enables security operators to immediately apply maximum security restrictions
        based on threat intelligence, compliance requirements, or incident response
        procedures. Bypasses normal risk assessment and applies immediate blocking.
        
        Args:
            source_ip (str): Source IP address to blacklist immediately
            duration (int): Blacklist duration in seconds (default: 1 hour)
            reason (str): Administrative justification for immediate blacklisting
        """
        # Apply immediate maximum security response with administrative authority
        self._apply_short_timeout_block(source_ip, duration, 1.0)
        self._add_to_blacklist(source_ip, duration, 1.0)
        
        self.logger.warning(f"🔧 ADMIN BLACKLIST: {source_ip} for {duration}s - {reason}")

    def manual_remove_mitigation(self, source_ip):
        """
        Administrative function to completely remove all security mitigations for a source.
        
        Provides security operators with emergency override capability to immediately
        remove all automated security restrictions. Used for false positive correction,
        emergency access restoration, or incident response requirements.
        
        Args:
            source_ip (str): Source IP address to clear of all security restrictions
            
        Returns:
            list: Actions removed for administrative audit trail
        """
        removed_actions = []
        
        if source_ip in self.rate_limited_sources:
            self._remove_rate_limiting(source_ip)
            removed_actions.append("rate_limiting")
        
        if source_ip in self.blocked_sources:
            self._unblock_source(source_ip, "Administrative emergency override")
            removed_actions.append("blocking")
        
        if source_ip in self.blacklist:
            del self.blacklist[source_ip]
            removed_actions.append("blacklist")
            
        self.logger.info(f"🔧 ADMIN MITIGATION REMOVAL: {source_ip} → Cleared: {removed_actions}")
        return removed_actions

    def get_current_lists(self):
        """Get current whitelist, blacklist, and honeypot IPs"""
        current_time = datetime.now()
        
        # Get active whitelist (non-expired)
        active_whitelist = {ip: entry for ip, entry in self.whitelist.items() 
                           if current_time < entry['expiry']}
        
        # Get active blacklist (non-expired)
        active_blacklist = {ip: entry for ip, entry in self.blacklist.items() 
                           if current_time < entry['expiry']}
        
        return {
            'whitelist': active_whitelist,
            'blacklist': active_blacklist,
            'honeypot_ips': self.honeypot_ips,
            'rate_limited': list(self.rate_limited_sources.keys()),
            'blocked': list(self.blocked_sources.keys())
        }

    def admin_add_to_whitelist(self, ip_address, reason="Admin manual addition"):
        """Admin function to add IP to whitelist"""
        try:
            # Validate IP format
            import ipaddress
            ipaddress.IPv4Address(ip_address)
            
            self._add_to_whitelist(ip_address, reason)
            
            # Remove any existing mitigations
            if ip_address in self.rate_limited_sources:
                self._remove_rate_limiting(ip_address)
            if ip_address in self.blocked_sources:
                self._unblock_source(ip_address, "Whitelisted by admin")
            
            self.logger.info(f"🔧 Admin added {ip_address} to whitelist: {reason}")
            return True, f"Successfully added {ip_address} to whitelist"
            
        except Exception as e:
            self.logger.error(f"❌ Admin whitelist addition failed for {ip_address}: {e}")
            return False, f"Failed to add {ip_address} to whitelist: {e}"

    def admin_add_to_blacklist(self, ip_address, duration=3600, reason="Admin manual addition"):
        """Admin function to add IP to blacklist"""
        try:
            # Validate IP format
            import ipaddress
            ipaddress.IPv4Address(ip_address)
            
            # Apply high-risk blocking immediately
            self._apply_short_timeout_block(ip_address, duration, 1.0)
            self._add_to_blacklist(ip_address, duration, 1.0)
            
            self.logger.warning(f"🔧 Admin added {ip_address} to blacklist for {duration}s: {reason}")
            return True, f"Successfully added {ip_address} to blacklist for {duration} seconds"
            
        except Exception as e:
            self.logger.error(f"❌ Admin blacklist addition failed for {ip_address}: {e}")
            return False, f"Failed to add {ip_address} to blacklist: {e}"

    def admin_remove_from_whitelist(self, ip_address):
        """Admin function to remove IP from whitelist"""
        try:
            if ip_address in self.whitelist:
                del self.whitelist[ip_address]
                self.logger.info(f"🔧 Admin removed {ip_address} from whitelist")
                return True, f"Successfully removed {ip_address} from whitelist"
            else:
                return False, f"{ip_address} not found in whitelist"
                
        except Exception as e:
            self.logger.error(f"❌ Admin whitelist removal failed for {ip_address}: {e}")
            return False, f"Failed to remove {ip_address} from whitelist: {e}"

    def admin_remove_from_blacklist(self, ip_address):
        """Admin function to remove IP from blacklist"""
        try:
            removed_actions = []
            
            if ip_address in self.blacklist:
                del self.blacklist[ip_address]
                removed_actions.append("blacklist_entry")
            
            if ip_address in self.blocked_sources:
                self._unblock_source(ip_address, "Admin manual removal")
                removed_actions.append("blocking_flows")
            
            if removed_actions:
                self.logger.info(f"🔧 Admin removed {ip_address} from blacklist: {removed_actions}")
                return True, f"Successfully removed {ip_address} from blacklist ({', '.join(removed_actions)})"
            else:
                return False, f"{ip_address} not found in blacklist"
                
        except Exception as e:
            self.logger.error(f"❌ Admin blacklist removal failed for {ip_address}: {e}")
            return False, f"Failed to remove {ip_address} from blacklist: {e}"

    def admin_add_honeypot(self, ip_address):
        """Admin function to add IP to honeypot list"""
        try:
            # Validate IP format
            import ipaddress
            ipaddress.IPv4Address(ip_address)
            
            self.honeypot_ips.add(ip_address)
            self.logger.warning(f"🍯 Admin added {ip_address} to honeypot list")
            return True, f"Successfully added {ip_address} to honeypot list"
            
        except Exception as e:
            self.logger.error(f"❌ Admin honeypot addition failed for {ip_address}: {e}")
            return False, f"Failed to add {ip_address} to honeypot list: {e}"

    def admin_remove_honeypot(self, ip_address):
        """Admin function to remove IP from honeypot list"""
        try:
            if ip_address in self.honeypot_ips:
                self.honeypot_ips.remove(ip_address)
                self.logger.info(f"🍯 Admin removed {ip_address} from honeypot list")
                return True, f"Successfully removed {ip_address} from honeypot list"
            else:
                return False, f"{ip_address} not found in honeypot list"
                
        except Exception as e:
            self.logger.error(f"❌ Admin honeypot removal failed for {ip_address}: {e}")
            return False, f"Failed to remove {ip_address} from honeypot list: {e}"

    def admin_clear_all_mitigations(self, ip_address):
        """Admin function to completely clear all mitigations for an IP"""
        try:
            cleared_actions = []
            
            # Remove from all lists
            if ip_address in self.whitelist:
                del self.whitelist[ip_address]
                cleared_actions.append("whitelist")
            
            if ip_address in self.blacklist:
                del self.blacklist[ip_address] 
                cleared_actions.append("blacklist")
            
            # Remove active mitigations
            if ip_address in self.rate_limited_sources:
                self._remove_rate_limiting(ip_address)
                cleared_actions.append("rate_limiting")
            
            if ip_address in self.blocked_sources:
                self._unblock_source(ip_address, "Admin complete clearance")
                cleared_actions.append("blocking")
            
            # Clear traffic history and risk profile
            if ip_address in self.traffic_history:
                del self.traffic_history[ip_address]
                cleared_actions.append("traffic_history")
            
            if ip_address in self.risk_profiles:
                del self.risk_profiles[ip_address]
                cleared_actions.append("risk_profile")
            
            if cleared_actions:
                self.logger.info(f"🔧 Admin cleared all mitigations for {ip_address}: {cleared_actions}")
                return True, f"Successfully cleared all mitigations for {ip_address} ({', '.join(cleared_actions)})"
            else:
                return False, f"No mitigations found for {ip_address}"
                
        except Exception as e:
            self.logger.error(f"❌ Admin complete clearance failed for {ip_address}: {e}")
            return False, f"Failed to clear mitigations for {ip_address}: {e}"

    def admin_get_ip_status(self, ip_address):
        """Get comprehensive status of an IP address"""
        try:
            current_time = datetime.now()
            status = {
                'ip_address': ip_address,
                'timestamp': current_time.isoformat(),
                'whitelist_status': None,
                'blacklist_status': None,
                'honeypot_status': ip_address in self.honeypot_ips,
                'active_mitigations': [],
                'risk_profile': None,
                'recent_activity': []
            }
            
            # Check whitelist status
            if ip_address in self.whitelist:
                entry = self.whitelist[ip_address]
                status['whitelist_status'] = {
                    'active': current_time < entry['expiry'],
                    'added_time': entry['added_time'].isoformat(),
                    'expiry': entry['expiry'].isoformat(),
                    'trust_score': self._calculate_whitelist_trust(entry),
                    'reason': entry['reason']
                }
            
            # Check blacklist status
            if ip_address in self.blacklist:
                entry = self.blacklist[ip_address]
                status['blacklist_status'] = {
                    'active': current_time < entry['expiry'],
                    'offense_count': entry['offense_count'],
                    'first_offense': entry['first_offense'].isoformat(),
                    'last_offense': entry['last_offense'].isoformat(),
                    'expiry': entry['expiry'].isoformat(),
                    'risk_score': entry['risk_score']
                }
            
            # Check active mitigations
            if ip_address in self.rate_limited_sources:
                status['active_mitigations'].append('rate_limiting')
            
            if ip_address in self.blocked_sources:
                status['active_mitigations'].append('blocking')
            
            # Get risk profile
            if ip_address in self.risk_profiles:
                profile = self.risk_profiles[ip_address]
                status['risk_profile'] = {
                    'first_seen': profile['first_seen'].isoformat(),
                    'average_risk': profile['average_risk'],
                    'peak_risk': profile['peak_risk'],
                    'honeypot_hits': profile['honeypot_hits'],
                    'recent_risk_scores': [r['risk_score'] for r in list(profile['risk_history'])[-10:]]
                }
            
            # Get recent activity
            if ip_address in self.traffic_history:
                recent_records = list(self.traffic_history[ip_address])[-10:]
                status['recent_activity'] = [{
                    'timestamp': r['timestamp'],
                    'risk_score': r.get('risk_score', 0),
                    'anomalous': r.get('anomalous', False),
                    'packet_count': r.get('packet_count', 0)
                } for r in recent_records]
            
            return status
            
        except Exception as e:
            self.logger.error(f"❌ Failed to get status for {ip_address}: {e}")
            return None

    def adjust_risk_thresholds(self, low_threshold=None, medium_threshold=None):
        """Dynamically adjust risk thresholds"""
        if low_threshold is not None:
            self.low_risk_threshold = max(0.0, min(1.0, low_threshold))
            
        if medium_threshold is not None:
            self.medium_risk_threshold = max(0.0, min(1.0, medium_threshold))
            
        # Ensure logical ordering
        if self.low_risk_threshold >= self.medium_risk_threshold:
            self.medium_risk_threshold = self.low_risk_threshold + 0.1
            
        self.logger.info(f"🎛️ Risk thresholds adjusted: LOW < {self.low_risk_threshold}, "
                        f"MEDIUM < {self.medium_risk_threshold}, HIGH >= {self.medium_risk_threshold}")

    def get_system_performance_metrics(self):
        """Get system performance and effectiveness metrics"""
        current_time = datetime.now()
        
        # Calculate processing metrics
        total_flows_processed = sum(len(history) for history in self.traffic_history.values())
        
        # Calculate mitigation effectiveness
        blocked_flows = len(self.blocked_sources)
        rate_limited_flows = len(self.rate_limited_sources)
        whitelisted_sources = len(self.whitelist)
        
        # Calculate response time metrics (simplified)
        avg_response_time = 0.1  # Would need actual timing measurements
        
        return {
            'processing_metrics': {
                'total_flows_processed': total_flows_processed,
                'unique_sources_monitored': len(self.risk_profiles),
                'average_response_time_ms': avg_response_time * 1000
            },
            'mitigation_effectiveness': {
                'blocked_sources': blocked_flows,
                'rate_limited_sources': rate_limited_flows,
                'whitelisted_sources': whitelisted_sources,
                'blacklisted_sources': len(self.blacklist),
                'mitigation_coverage': (blocked_flows + rate_limited_flows) / max(len(self.risk_profiles), 1)
            },
            'system_health': {
                'active_meters': sum(len(meters) for meters in self.meter_registry.values()),
                'memory_usage_sources': len(self.risk_profiles),
                'monitoring_thread_active': self.monitoring_active
            }
        }

    def evaluate_flow_security(self, source_ip, dest_ip, flow_stats):
        """
        Evaluate flow security status using consolidated security policies.
        
        Centralized security evaluation method that consolidates whitelist, blacklist,
        and honeypot checks for improved modularity. This method handles all initial
        security policy checks, eliminating the need for duplicate checks in 
        risk_based_mitigation() method. Called by the SDN controller during flow 
        statistics analysis to determine immediate security response actions.
        
        Optimization: This method performs all security policy checks once, avoiding
        redundant honeypot/whitelist/blacklist checks in other methods.
        
        Args:
            source_ip (str): Source IP address to evaluate
            dest_ip (str): Destination IP address to check for honeypot
            flow_stats: OpenFlow statistics for the flow
            
        Returns:
            dict: Security evaluation results with action recommendations:
                - ALLOW: Whitelisted sources (trusted)
                - BLOCK: Blacklisted sources (known threats)  
                - HONEYPOT_HIT: Critical honeypot access (immediate block)
                - ANALYZE: Requires ML-based risk analysis
                - ERROR: Evaluation failed (fallback to ML analysis)
        """
        try:
            current_time = datetime.now()
            
            # Check whitelist status first (trusted sources bypass all other checks)
            if source_ip in self.whitelist:
                whitelist_entry = self.whitelist[source_ip]
                
                # Verify whitelist entry hasn't expired
                if current_time < whitelist_entry['expiry']:
                    # Update last activity and trust score
                    whitelist_entry['last_activity'] = current_time
                    current_trust = self._calculate_whitelist_trust(whitelist_entry)
                    
                    if current_trust > 0.5:  # Still trusted
                        return {
                            'action': 'ALLOW',
                            'priority': 'LOW',
                            'reason': f'Whitelisted source (trust: {current_trust:.2f})',
                            'whitelisted': True,
                            'trust_score': current_trust
                        }
                    else:
                        # Trust has decayed, remove from whitelist
                        del self.whitelist[source_ip]
                        self.logger.info(f"⚪ Removed {source_ip} from whitelist due to trust decay")
                else:
                    # Expired whitelist entry
                    del self.whitelist[source_ip]
                    self.logger.info(f"⚪ Removed expired whitelist entry for {source_ip}")
            
            # Check blacklist status (blocked sources)
            if source_ip in self.blacklist:
                blacklist_entry = self.blacklist[source_ip]
                
                # Verify blacklist entry hasn't expired
                if current_time < blacklist_entry['expiry']:
                    return {
                        'action': 'BLOCK',
                        'priority': 'HIGH',
                        'reason': f'Blacklisted source (offense #{blacklist_entry["offense_count"]})',
                        'blacklisted': True,
                        'offense_count': blacklist_entry['offense_count']
                    }
                else:
                    # Expired blacklist entry
                    del self.blacklist[source_ip]
                    self.logger.info(f"⚫ Removed expired blacklist entry for {source_ip}")
            
            # Check honeypot hit (critical security event - highest priority)
            if dest_ip in self.honeypot_ips:
                # Handle honeypot hit with immediate maximum security response
                honeypot_response = self._handle_honeypot_hit(source_ip, dest_ip, flow_stats)
                return honeypot_response
            
            # Default response for unclassified sources
            return {
                'action': 'ANALYZE',
                'priority': 'MEDIUM',
                'reason': 'Source requires ML-based risk analysis',
                'requires_ml_analysis': True
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error evaluating flow security for {source_ip}: {e}")
            return {
                'action': 'ERROR',
                'priority': 'MEDIUM',
                'reason': f'Security evaluation failed: {e}',
                'requires_ml_analysis': True  # Fallback to ML analysis
            }

    def get_current_lists(self):
        """
        Retrieve current security policy lists for administrative dashboard display.
        
        Provides consolidated view of all active security policies for operational
        monitoring and administrative management interfaces. Used by web dashboards,
        CLI tools, and API endpoints for real-time security policy visualization.
        
        Returns:
            dict: Current security policy lists including whitelist, blacklist, and honeypot IPs
        """
        return {
            'whitelist': list(self.whitelist.keys()) if hasattr(self, 'whitelist') else [],
            'blacklist': list(self.blacklist.keys()),
            'honeypot': list(self.honeypot_ips),
            'rate_limited': list(self.rate_limited_sources.keys()),
            'blocked': list(self.blocked_sources.keys())
        }


# Legacy Compatibility Support
# Maintains backward compatibility with existing integrations and legacy code
# that may reference the original MitigationManager class name or interface
MitigationManager = RiskBasedMitigationManager  # Legacy alias for backward compatibility
