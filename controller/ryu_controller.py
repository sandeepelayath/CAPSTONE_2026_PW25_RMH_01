import ssl
import time
import sys
import os

# Fix SSL recursion issue before any other imports
if not hasattr(ssl.SSLContext, "_fixed_minimum_version"):
    # Store original descriptor safely
    original_minimum_version = getattr(ssl.SSLContext, 'minimum_version', None)
    
    def safe_get_minimum_version(self):
        return getattr(self, '_min_version', ssl.TLSVersion.TLSv1_2)
    
    def safe_set_minimum_version(self, value):
        # Validate the value first
        if not isinstance(value, ssl.TLSVersion):
            return
        self._min_version = value
    
    # Replace with our safe implementation
    ssl.SSLContext.minimum_version = property(safe_get_minimum_version, safe_set_minimum_version)
    ssl.SSLContext._fixed_minimum_version = True

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib import hub
import logging
import json
import threading
import time
from datetime import datetime
from mitigation_manager import RiskBasedMitigationManager

try:
    from flow_classifier import FlowClassifier
    print("✅ Successfully imported FlowClassifier from flow_classifier module")
except ImportError as e:
    print(f"⚠️ FlowClassifier import failed: {e}. Using fallback classifier.")
    # Create a simple fallback classifier
    class FlowClassifier:
        def classify_flow(self, flow_stats):
            # Simple fallback: very low anomaly detection rate
            packet_count = getattr(flow_stats, 'packet_count', 0)
            duration_sec = getattr(flow_stats, 'duration_sec', 1)
            
            # Only flag as anomaly if very high packet rate
            packets_per_second = packet_count / max(duration_sec, 1)
            if packets_per_second > 200:  # Very high threshold
                return True, 0.6
            return False, 0.1

class AnomalyDetectionController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AnomalyDetectionController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.flow_classifier = FlowClassifier()
        self.mitigation_manager = RiskBasedMitigationManager(
            controller_ref=self,
            low_risk_threshold=0.08,
            medium_risk_threshold=0.25,
            high_risk_threshold=0.35,
            base_rate_limit_pps=1000,
            base_rate_limit_bps=1000000,
            base_blacklist_timeout=60,
            max_blacklist_timeout=3600
        )
        self.monitor_thread = hub.spawn(self._monitor)
        self.mac_to_port = {}
        self.mac_to_ip = {}
        # --- Whitelist and Blacklist ---
        self.whitelist = set([
            # '10.0.0.1',  # Normal user host (h1) - whitelisted by default (COMMENTED OUT FOR TESTING)
            # '10.0.0.2',  # Web server host (h2) - whitelisted by default (COMMENTED OUT FOR TESTING)
            # Add trusted IPs here, e.g. '10.0.0.1', '10.0.0.2'
        ])
        self.blacklist = set()
        
        # Server/Infrastructure IPs that should NOT be analyzed as attack sources
        # These hosts are legitimate servers that send response traffic
        self.server_ips = {
            '10.0.0.1',  # h1 - Normal user host (can also run services)
            '10.0.0.2',  # h2 - Web server host
            # Add other server/infrastructure IPs here
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info(f"✅ Switch {datapath.id} connected")

        datapath.send_msg(parser.OFPSetConfig(datapath, ofproto.OFPC_FRAG_NORMAL, 65535))

        # Table-miss flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.datapaths[datapath.id] = datapath

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=inst,
            buffer_id=(buffer_id if buffer_id is not None else ofproto.OFP_NO_BUFFER)
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        # Learn MAC to IP mapping from ARP packets
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt:
                self.mac_to_ip[arp_pkt.src_mac] = arp_pkt.src_ip
                self.logger.debug(f"ARP Cache: Learned {arp_pkt.src_mac} -> {arp_pkt.src_ip}")

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(2)  # Reduced from 10s to 2s for faster anomaly reporting

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        flows_to_process = [flow for flow in body if flow.priority == 1]
        
        for stat in sorted(flows_to_process, 
                           key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])):
            source_ip = self._extract_source_ip(stat)
            dest_ip = self._extract_dest_ip(stat)
            
            # Log flow details for debugging
            #self.logger.debug(f"[DEBUG] Processing flow: source_ip={source_ip}, dest_ip={dest_ip}, "
                            #f"packet_count={stat.packet_count}, duration_sec={stat.duration_sec}")

            # --- Step 1: Whitelist Check ---
            if source_ip and source_ip in self.whitelist:
                #self.logger.debug(f"✅ Whitelisted source {source_ip}: traffic allowed (dest: {dest_ip}, packets: {stat.packet_count}), skipping all mitigation.")
                continue

            # --- Step 2: Blacklist Check ---
            elif source_ip and source_ip in self.blacklist:
                self.logger.warning(f"🚫 Blacklisted source {source_ip}: traffic blocked immediately.")
                # Remove flow if present
                try:
                    datapath = ev.msg.datapath
                    self.remove_flow(datapath, stat.match)
                except Exception as e:
                    self.logger.error(f"Failed to remove blacklisted flow: {e}")
                continue

            # --- Step 3: Honeypot Tripwire ---
            elif dest_ip and dest_ip in self.mitigation_manager.honeypot_ips:
                self.logger.warning(f"[DEBUG] Honeypot tripwire check: dest_ip={dest_ip}, honeypot_ips={self.mitigation_manager.honeypot_ips}, source_ip={source_ip}")
                if source_ip:
                    self.logger.warning(f"🚨 HONEYPOT TRIPWIRE: {source_ip} -> {dest_ip}. Assigning risk=1.0, blacklisting, and blocking.")
                    self.blacklist.add(source_ip)
                    mitigation_action = self.mitigation_manager.risk_based_mitigation(
                        flow_stats=stat,
                        ml_confidence=1.0,
                        source_ip=source_ip,
                        dest_ip=dest_ip,
                        force_block=True
                    )
                    if mitigation_action:
                        self.logger.info(f"🛡️ Applied {mitigation_action['action']} for {source_ip} (honeypot tripwire)")
                    # Remove flow
                    try:
                        datapath = ev.msg.datapath
                        self.remove_flow(datapath, stat.match)
                        self.logger.info(f"[DEBUG] Removed flow for honeypot tripwire: {stat.match}")
                    except Exception as e:
                        self.logger.error(f"Failed to remove honeypot flow: {e}")

                    # Install highest-priority drop rule for attacker-honeypot traffic
                    try:
                        parser = datapath.ofproto_parser
                        ofproto = datapath.ofproto
                        drop_match = parser.OFPMatch(ipv4_src=source_ip, ipv4_dst=dest_ip, eth_type=0x0800)
                        drop_actions = []  # No actions = drop
                        # Use highest possible priority (32767 for OpenFlow 1.3)
                        self.add_flow(datapath, 32767, drop_match, drop_actions)
                        self.logger.info(f"🚫 [DEBUG] Installed highest-priority drop rule: {source_ip} -> {dest_ip} (honeypot protection)")
                    except Exception as e:
                        self.logger.error(f"Failed to install drop rule for honeypot: {e}")
                    continue
                else:
                    self.logger.error(f"🚨 HONEYPOT HIT detected, but could not extract a source IP to block. Flow: {stat.match}")
                    continue

            # --- Step 4: Smart Flow Direction Analysis ---
            # Check if this flow should be analyzed based on source/destination
            if not self._should_analyze_flow_for_attacks(source_ip, dest_ip):
                continue  # Skip analysis for server response traffic
                
            # --- Step 5: Risk-Based Mitigation Tiers ---
            else:
                self.logger.debug(f"[DEBUG] Calling flow_classifier.classify_flow for flow with packet_count={stat.packet_count}")
                is_anomaly, confidence = self.flow_classifier.classify_flow(stat)
                self.logger.debug(f"[DEBUG] Classification result: is_anomaly={is_anomaly}, confidence={confidence}")
                
                if is_anomaly:
                    self.logger.warning(f"🚨 Anomaly Detected in Flow {stat.match} (Confidence: {confidence:.3f})")
                    if source_ip:
                        self.logger.info(f"🛡️ Applying risk-based mitigation for source {source_ip}")
                        mitigation_action = self.mitigation_manager.risk_based_mitigation(
                            flow_stats=stat,
                            ml_confidence=confidence,
                            source_ip=source_ip,
                            dest_ip=dest_ip
                        )
                        if mitigation_action:
                            self.logger.info(f"🛡️ Applied {mitigation_action['action']} for {source_ip} (Risk: {mitigation_action['risk_level']})")
                            # If action is BLOCK or risk is critical, add to blacklist
                            if mitigation_action['action'] == 'BLOCK' or mitigation_action.get('risk_level') == 'critical':
                                self.blacklist.add(source_ip)
                                self.logger.info(f"🚫 Source {source_ip} added to blacklist due to critical risk.")
                            # If action is REDIRECT_TO_HONEYPOT, do not update honeypot_ips (keep static)
                        else:
                            self.logger.warning(f"⚠️ Failed to apply mitigation for {source_ip}")
                    else:
                        source_mac = self._extract_source_mac(stat)
                        if source_mac and source_mac != '00:00:00:00:00:01':
                            self.logger.info(f"⚠️ Detected L2 anomaly from MAC {source_mac}. Logging event.")
                            self.mitigation_manager.log_l2_anomaly(
                                source_mac=source_mac,
                                confidence=confidence,
                                flow_stats=stat
                            )
                        elif not source_mac:
                            self.logger.warning("⚠️ Could not extract any source identifier from flow. Logging raw anomaly.")
                            self.mitigation_manager.log_unidentified_anomaly(confidence, stat)
                    # Remove flows for very high confidence IP-based anomalies
                    if confidence > 0.9 and source_ip:
                        try:
                            datapath = ev.msg.datapath
                            self.remove_flow(datapath, stat.match)
                            self.logger.info(f"🚫 Removed high-confidence anomalous flow: {stat.match}")
                        except Exception as e:
                            self.logger.error(f"Failed to remove anomalous flow: {e}")

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == ofproto_v1_3.OFPPR_DELETE:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.warning(f"❌ Switch {datapath.id} disconnected")

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def _error_msg_handler(self, ev):
        self.logger.error(f"⚠️ OpenFlow Error: {ev.msg}")

    def _should_analyze_flow_for_attacks(self, source_ip, dest_ip):
        """
        Determine if a flow should be analyzed for attack patterns.
        
        Args:
            source_ip: Source IP of the flow
            dest_ip: Destination IP of the flow
            
        Returns:
            bool: True if flow should be analyzed, False if it should be ignored
            
        Logic:
            - Ignore flows from servers to clients (server responses)
            - Analyze flows from clients to servers (potential attacks)
            - Analyze flows between clients (lateral movement)
        """
        if not source_ip:
            return False  # Can't analyze without source IP
            
        # If source is a server, this is likely response traffic - don't analyze
        if source_ip in self.server_ips:
            self.logger.debug(f"🔄 Ignoring flow from server {source_ip} -> {dest_ip or 'unknown'} (server response traffic)")
            return False
            
        # If destination is a server, this is client->server traffic - analyze it
        if dest_ip and dest_ip in self.server_ips:
            self.logger.debug(f"🔍 Analyzing flow {source_ip} -> {dest_ip} (client->server traffic)")
            return True
            
        # For other flows (client->client, unknown destinations), analyze them
        self.logger.debug(f"🔍 Analyzing flow {source_ip} -> {dest_ip or 'unknown'} (non-server source)")
        return True

    def add_server_ip(self, ip):
        """Add an IP to the server list (won't be analyzed as attack source)"""
        self.server_ips.add(ip)
        self.logger.info(f"📡 Added {ip} to server list - will not be analyzed as attack source")
        
    def remove_server_ip(self, ip):
        """Remove an IP from the server list"""
        if ip in self.server_ips:
            self.server_ips.remove(ip)
            self.logger.info(f"🔄 Removed {ip} from server list - will now be analyzed normally")
        
    def get_server_ips(self):
        """Get current list of server IPs"""
        return set(self.server_ips)

    def _extract_source_ip(self, flow_stat):
        """
        Extract source IP address from flow statistics, using MAC-to-IP cache as a fallback.
        Returns the IP address as a string, or None if no IPv4 source is found.
        """
        match = flow_stat.match
        
        # Primary method: Check for 'ipv4_src' in the match dictionary directly
        if 'ipv4_src' in match:
            return match['ipv4_src']
        
        # Fallback for different match representations
        if hasattr(match, 'get'):
            ip = match.get('ipv4_src')
            if ip:
                return ip

        # Second fallback: Try to resolve the MAC address to an IP from our cache
        mac = self._extract_source_mac(flow_stat)
        if mac and mac in self.mac_to_ip:
            resolved_ip = self.mac_to_ip[mac]
            self.logger.debug(f"Resolved MAC {mac} to IP {resolved_ip} from cache.")
            return resolved_ip

        # If no IP address is found, return None.
        return None

    def _extract_source_mac(self, stat):
        """
        Extract source MAC address from flow statistics.
        Returns the MAC address as a string, or None if no Ethernet source is found.
        """
        match = stat.match
        
        # Primary method: Check for 'eth_src' in the match dictionary directly
        if 'eth_src' in match:
            return match['eth_src']
        
        # Fallback for different match representations if the above fails
        if hasattr(match, 'get'):
            mac = match.get('eth_src')
            if mac:
                return mac
        
        # If no MAC address is found, return None
        return None

    def _extract_dest_ip(self, stat):
        """
        Extract destination IP address from flow statistics.
        """
        match = stat.match
        if 'ipv4_dst' in match:
            return match['ipv4_dst']
        if hasattr(match, 'get'):
            return match.get('ipv4_dst')
        return None

    def _resolve_mac_to_ip(self, mac_address):
        """Attempt to resolve MAC address to IP using ARP table or host tracking"""
        # Simple implementation - in production, you'd maintain an ARP table
        # For now, we'll return None to avoid IP-based mitigation for MAC-only flows
        return None

    def remove_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Use oxm_fields if available
        if hasattr(match, 'oxm_fields') and match.oxm_fields:
            match_dict = match.oxm_fields.copy()
        else:
            # Fallback for field iteration
            match_dict = {}
            try:
                for field in match.fields:
                    if hasattr(field, 'header') and hasattr(field, 'value'):
                        if hasattr(field.header, 'type_'):
                            # Map OXM types to field names
                            if field.header.type_ == 0x80000602:  # OXM_OF_ETH_SRC
                                match_dict['eth_src'] = field.value
                            elif field.header.type_ == 0x80000704:  # OXM_OF_ETH_DST
                                match_dict['eth_dst'] = field.value
                            elif field.header.type_ == 0x80000204:  # OXM_OF_IN_PORT
                                match_dict['in_port'] = field.value
                            elif field.header.type_ == 0x80000c04:  # OXM_OF_IPV4_SRC
                                match_dict['ipv4_src'] = field.value
                            elif field.header.type_ == 0x80000e04:  # OXM_OF_IPV4_DST
                                match_dict['ipv4_dst'] = field.value
            except Exception as e:
                self.logger.error(f"Error parsing match fields: {e}")
                return
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch(**match_dict)
        )
        datapath.send_msg(mod)
        self.logger.info("Removed anomalous flow from switch %s", datapath.id)

    # Additional methods for risk-based management
    def get_risk_analytics(self):
        """Get comprehensive risk analytics from the mitigation manager"""
        return self.mitigation_manager.get_risk_analytics()
    
    def get_source_analysis(self, source_ip):
        """Get detailed analysis for a specific source"""
        return self.mitigation_manager.get_source_detailed_analysis(source_ip)
    
    def manual_whitelist_source(self, source_ip, reason="Manual admin action"):
        """Manually whitelist a source (for admin intervention)"""
        self.mitigation_manager.manual_whitelist(source_ip, reason)
        self.logger.info(f"🔧 Manually whitelisted {source_ip}: {reason}")
    
    def manual_blacklist_source(self, source_ip, duration=3600, reason="Manual admin action"):
        """Manually blacklist a source (for admin intervention)"""
        self.mitigation_manager.manual_blacklist(source_ip, duration, reason)
        self.logger.warning(f"🔧 Manually blacklisted {source_ip} for {duration}s: {reason}")
    
    def remove_all_mitigations(self, source_ip):
        """Remove all active mitigations for a source"""
        removed = self.mitigation_manager.manual_remove_mitigation(source_ip)
        self.logger.info(f"🔧 Removed mitigations for {source_ip}: {removed}")
        return removed
    
    # Enhanced Admin Management Methods
    def admin_add_to_whitelist(self, ip_address, reason="Admin addition"):
        """Admin function to add IP to whitelist"""
        success, message = self.mitigation_manager.admin_add_to_whitelist(ip_address, reason)
        self.logger.info(f"🔧 Admin whitelist operation: {message}")
        return success, message
    
    def admin_add_to_blacklist(self, ip_address, duration=3600, reason="Admin addition"):
        """Admin function to add IP to blacklist"""
        success, message = self.mitigation_manager.admin_add_to_blacklist(ip_address, duration, reason)
        self.logger.warning(f"🔧 Admin blacklist operation: {message}")
        return success, message
    
    def admin_remove_from_whitelist(self, ip_address):
        """Admin function to remove IP from whitelist"""
        success, message = self.mitigation_manager.admin_remove_from_whitelist(ip_address)
        self.logger.info(f"🔧 Admin whitelist removal: {message}")
        return success, message
    
    def admin_remove_from_blacklist(self, ip_address):
        """Admin function to remove IP from blacklist"""
        success, message = self.mitigation_manager.admin_remove_from_blacklist(ip_address)
        self.logger.info(f"🔧 Admin blacklist removal: {message}")
        return success, message
    
    def admin_add_honeypot(self, ip_address):
        """Admin function to add IP to honeypot list"""
        success, message = self.mitigation_manager.admin_add_honeypot(ip_address)
        self.logger.warning(f"🔧 Admin honeypot addition: {message}")
        return success, message
    
    def admin_remove_honeypot(self, ip_address):
        """Admin function to remove IP from honeypot list"""
        success, message = self.mitigation_manager.admin_remove_honeypot(ip_address)
        self.logger.info(f"🔧 Admin honeypot removal: {message}")
        return success, message
    
    def admin_clear_all_mitigations(self, ip_address):
        """Admin function to completely clear all mitigations for an IP"""
        success, message = self.mitigation_manager.admin_clear_all_mitigations(ip_address)
        self.logger.info(f"🔧 Admin complete clearance: {message}")
        return success, message
    
    def admin_get_ip_status(self, ip_address):
        """Get comprehensive status of an IP address"""
        return self.mitigation_manager.admin_get_ip_status(ip_address)
    
    def admin_add_server(self, ip_address):
        """Add an IP to the server list (admin method)"""
        self.add_server_ip(ip_address)
        return f"Added {ip_address} to server list"
        
    def admin_remove_server(self, ip_address):
        """Remove an IP from the server list (admin method)"""
        self.remove_server_ip(ip_address)
        return f"Removed {ip_address} from server list"
        
    def admin_list_servers(self):
        """List all current server IPs (admin method)"""
        return list(self.get_server_ips())
    
    def get_current_ip_lists(self):
        """Get current whitelist, blacklist, and honeypot IPs"""
        return self.mitigation_manager.get_current_lists()
