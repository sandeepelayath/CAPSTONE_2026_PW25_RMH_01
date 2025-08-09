import ssl
from ssl import TLSVersion

# Only apply once
if not hasattr(ssl.SSLContext, "_original_minimum_version"):

    original_property = ssl.SSLContext.__dict__.get("minimum_version")

    def get_minimum_version(self):
        return getattr(self, "_custom_minimum_version", TLSVersion.TLSv1_2)

    def set_minimum_version(self, value):
        setattr(self, "_custom_minimum_version", value)

    # Replace with safe property
    ssl.SSLContext.minimum_version = property(get_minimum_version, set_minimum_version)
    ssl.SSLContext._original_minimum_version = original_property


import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types
from flow_classifier import FlowClassifier
from mitigation_manager import MitigationManager

# Patch SSL minimum version if needed
# Safe SSL monkey patch (no recursion)
if not hasattr(ssl.SSLContext, "_patched_minimum_version"):
    real_minimum_version = ssl.SSLContext.__dict__.get("minimum_version", None)

    if isinstance(real_minimum_version, property):
        def get_minimum_version(self):
            return getattr(self, "_minimum_version", ssl.TLSVersion.TLSv1_2)

        def set_minimum_version(self, value):
            self._minimum_version = value

        ssl.SSLContext.minimum_version = property(get_minimum_version, set_minimum_version)
        ssl.SSLContext._patched_minimum_version = True



class AnomalyDetectionController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AnomalyDetectionController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.flow_classifier = FlowClassifier()
        self.mitigation_manager = MitigationManager(controller_ref=self)
        self.monitor_thread = hub.spawn(self._monitor)
        self.mac_to_port = {}  # MAC learning table

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
            hub.sleep(10)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        for stat in body:
            try:
                if stat.priority == 0:
                    continue

                anomaly_result = self.flow_classifier.classify_flow(stat)
                if isinstance(anomaly_result, tuple):
                    is_anomaly, confidence = anomaly_result
                else:
                    is_anomaly, confidence = anomaly_result, 0.8  # Default confidence
                
                if is_anomaly:
                    self.logger.warning(f"🚨 Anomaly Detected in Flow {stat.match} (Confidence: {confidence:.3f})")
                    
                    # Use advanced mitigation strategy
                    source_ip = self._extract_source_ip(stat)
                    if source_ip:
                        self.mitigation_manager.detect_anomaly_and_mitigate(stat, confidence, source_ip=source_ip)
                    else:
                        self.logger.warning("⚠️ Could not extract source IP/MAC from flow")
                    
                    # Still remove the immediate flow as backup
                    try:
                        datapath = ev.msg.datapath
                        self.remove_flow(datapath, stat.match)
                        self.logger.info(f"🚫 Removed anomalous flow: {stat.match}")
                    except Exception as e:
                        self.logger.error(f"Failed to remove anomalous flow: {e}")
            except Exception as e:
                self.logger.error(f"Error processing flow stats: {e}")
                import traceback
                traceback.print_exc()

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

    def _extract_source_ip(self, stat):
        match = stat.match
        # Try to get from oxm_fields dictionary first
        if hasattr(match, 'oxm_fields') and match.oxm_fields:
            if 'eth_src' in match.oxm_fields:
                return match.oxm_fields['eth_src']
            elif 'ipv4_src' in match.oxm_fields:
                return match.oxm_fields['ipv4_src']
        
        # Direct string parsing from the match representation as backup
        match_str = str(match)
        if 'eth_src' in match_str:
            import re
            eth_match = re.search(r"'eth_src': '([^']+)'", match_str)
            if eth_match:
                return eth_match.group(1)
        elif 'ipv4_src' in match_str:
            import re
            ip_match = re.search(r"'ipv4_src': '([^']+)'", match_str)
            if ip_match:
                return ip_match.group(1)
        
        # Fallback: iterate through fields with proper attribute access
        try:
            for field in match.fields:
                # Handle different field types
                if hasattr(field, 'header') and hasattr(field, 'value'):
                    if hasattr(field.header, 'type_'):
                        # Check for ethernet source
                        if field.header.type_ == 0x80000602:  # OXM_OF_ETH_SRC
                            return field.value
                        # Check for IPv4 source  
                        elif field.header.type_ == 0x80000c04:  # OXM_OF_IPV4_SRC
                            return field.value
        except Exception as e:
            self.logger.debug(f"Could not parse match fields: {e}")
        
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
