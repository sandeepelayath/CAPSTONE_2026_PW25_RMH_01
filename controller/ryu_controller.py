import ssl

# Apply a monkey-patch if it hasn't been applied already
if not hasattr(ssl.SSLContext, "_patched_minimum_version"):
    def get_minimum_version(self):
        return self.__dict__.get("_minimum_version", None)
    
    def set_minimum_version(self, value):
        self.__dict__["_minimum_version"] = value

    ssl.SSLContext.minimum_version = property(get_minimum_version, set_minimum_version)
    ssl.SSLContext._patched_minimum_version = True

import ssl
import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types
from flow_classifier import FlowClassifier

# Patch SSL minimum version if needed
if not hasattr(ssl.SSLContext, "_patched_minimum_version"):
    def get_minimum_version(self):
        return self.__dict__.get("_minimum_version", None)

    def set_minimum_version(self, value):
        self.__dict__["_minimum_version"] = value

    ssl.SSLContext.minimum_version = property(get_minimum_version, set_minimum_version)
    ssl.SSLContext._patched_minimum_version = True

class AnomalyDetectionController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AnomalyDetectionController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.flow_classifier = FlowClassifier()
        self.monitor_thread = hub.spawn(self._monitor)
        self.mac_to_port = {}  # Initialize MAC-to-port dictionary

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handles switch connection and ensures OpenFlow 1.3 is set."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info(f"✅ Switch {datapath.id} connected")

        # Ensure OpenFlow 1.3 is set
        datapath.send_msg(parser.OFPSetConfig(datapath, ofproto.OFPC_FRAG_NORMAL, 65535))

        # Install a table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.datapaths[datapath.id] = datapath

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Adds a flow entry to the switch."""
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
        """Handles incoming packets and applies MAC learning."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # Initialize mac_to_port for this switch
        self.mac_to_port.setdefault(dpid, {})

        # Learn MAC address
        self.mac_to_port[dpid][src] = in_port

        # Determine output port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow entry for known hosts
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        # Forward the packet
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _monitor(self):
        """Periodically requests flow stats from all switches."""
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        """Requests flow statistics from the switch."""
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Processes flow statistics and detects anomalies."""
        body = ev.msg.body
        for stat in body:
            try:
                is_anomaly = self.flow_classifier.classify_flow(stat)
                if is_anomaly:
                    self.logger.warning(f"🚨 Anomaly Detected in Flow {stat.match}")
            except Exception as e:
                self.logger.error(f"Error processing flow stats: {e}")

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def _state_change_handler(self, ev):
        """Handles switch disconnects and removes stale datapaths."""
        datapath = ev.datapath
        if ev.state == ofproto_v1_3.OFPPR_DELETE:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.warning(f"❌ Switch {datapath.id} disconnected")

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def _error_msg_handler(self, ev):
        """Handles OpenFlow error messages."""
        self.logger.error(f"⚠️ OpenFlow Error: {ev.msg}")
