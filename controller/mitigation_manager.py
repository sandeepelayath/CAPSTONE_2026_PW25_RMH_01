#!/usr/bin/env python3
"""
Advanced Mitigation Manager for SDN-based Cybersecurity System
Implements intelligent source-based blocking, traffic analysis, and adaptive unblocking
"""

import time
import json
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging


class MitigationManager:
    def __init__(self, controller_ref, block_duration=300, analysis_window=60, 
                 threat_threshold=0.7, unblock_confidence_threshold=0.3):
        """
        Initialize the Mitigation Manager
        
        Args:
            controller_ref: Reference to the Ryu controller
            block_duration: Default block duration in seconds (5 minutes)
            analysis_window: Time window for behavior analysis in seconds
            threat_threshold: Confidence threshold to trigger blocking
            unblock_confidence_threshold: Confidence threshold to unblock
        """
        self.controller = controller_ref
        self.block_duration = block_duration
        self.analysis_window = analysis_window
        self.threat_threshold = threat_threshold
        self.unblock_confidence_threshold = unblock_confidence_threshold
        
        # Tracking dictionaries
        self.blocked_sources = {}  # {source_ip: BlockInfo}
        self.traffic_history = defaultdict(deque)  # {source_ip: [TrafficRecord]}
        self.anomaly_counts = defaultdict(int)  # {source_ip: count}
        self.legitimate_behavior = defaultdict(list)  # {source_ip: [normal_patterns]}
        
        # Logging setup
        self.setup_logging()
        
        # Start background monitoring thread
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._background_monitor)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.logger.info("🛡️ Mitigation Manager initialized with intelligent blocking")

    def setup_logging(self):
        """Set up comprehensive logging system"""
        self.logger = logging.getLogger('MitigationManager')
        self.logger.setLevel(logging.INFO)
        
        # Create file handler for mitigation logs
        handler = logging.FileHandler('mitigation_log.json')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def detect_anomaly_and_mitigate(self, flow_stats, anomaly_confidence, source_ip=None):
        """
        Main entry point when anomaly is detected
        
        Args:
            flow_stats: OpenFlow statistics
            anomaly_confidence: ML model confidence score
            source_ip: Source IP address (extracted if None)
        """
        try:
            # Extract source IP if not provided
            if source_ip is None:
                source_ip = self._extract_source_ip(flow_stats)
            
            if source_ip is None:
                self.logger.warning("⚠️ Could not extract source IP from flow")
                return
            
            # Record the anomaly
            self._record_anomaly(source_ip, flow_stats, anomaly_confidence)
            
            # Check if blocking criteria is met
            if self._should_block_source(source_ip, anomaly_confidence):
                self._block_source(source_ip, anomaly_confidence, flow_stats)
            else:
                self._log_suspicious_activity(source_ip, anomaly_confidence, flow_stats)
                
        except Exception as e:
            self.logger.error(f"❌ Error in anomaly mitigation: {e}")

    def _extract_source_ip(self, flow_stats):
        """Extract source IP from flow statistics"""
        try:
            if hasattr(flow_stats, 'match'):
                match_dict = flow_stats.match.to_jsondict().get('OFPMatch', {})
                return match_dict.get('ipv4_src', match_dict.get('eth_src'))
            return None
        except Exception as e:
            self.logger.error(f"❌ Error extracting source IP: {e}")
            return None

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
        Install blocking flows in all connected switches
        """
        try:
            for datapath in self.controller.datapaths.values():
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                
                # Block all traffic from this source IP
                match = parser.OFPMatch(ipv4_src=source_ip)
                
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
                self.logger.info(f"🚫 Installed blocking flow for {source_ip} on switch {datapath.id}")
                
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
        Background thread for monitoring and adaptive unblocking
        """
        while self.monitoring_active:
            try:
                self._check_unblock_conditions()
                self._cleanup_old_data()
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                self.logger.error(f"❌ Error in background monitor: {e}")

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
        Remove blocking flows from all switches
        """
        try:
            for datapath in self.controller.datapaths.values():
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                
                # Match the blocking rule
                match = parser.OFPMatch(ipv4_src=source_ip)
                
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

    def get_threat_analysis(self, source_ip):
        """
        Get detailed threat analysis for a specific source
        """
        if source_ip not in self.traffic_history:
            return None
            
        records = list(self.traffic_history[source_ip])
        recent_anomalies = self._count_recent_anomalies(source_ip, minutes=10)
        
        return {
            'source_ip': source_ip,
            'total_records': len(records),
            'anomaly_count': self.anomaly_counts[source_ip],
            'recent_anomalies': recent_anomalies,
            'is_blocked': source_ip in self.blocked_sources,
            'attack_pattern_detected': self._is_attack_pattern(source_ip),
            'threat_level': self._calculate_threat_level(source_ip)
        }

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

    def _write_log_entry(self, log_entry):
        """Write log entry to JSON log file"""
        try:
            with open('mitigation_actions.json', 'a') as f:
                json.dump(log_entry, f)
                f.write('\n')
        except Exception as e:
            self.logger.error(f"❌ Error writing log entry: {e}")

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

    def shutdown(self):
        """Shutdown the mitigation manager"""
        self.monitoring_active = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join()
        self.logger.info("🛡️ Mitigation Manager shutdown complete")