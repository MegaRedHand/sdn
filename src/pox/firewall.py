#!/usr/bin/env python3
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.revent.revent import EventMixin
from pox.lib.util import dpidToStr, dpid_to_str
from pox.lib.addresses import EthAddr, IPAddr
from collections import namedtuple
import pox.lib.packet as pkt
import os

# Add your imports here ...
log = core.getLogger()

# Add your global variables here ...
class Firewall(EventMixin):
    def __init__(self):
        super().__init__()
        self.listenTo(core.openflow)
        log.info("Enabling Firewall Module")

    # Forwards packets headed to dst_ip to the correct switch output_port
    def establish_flow_to_hosts(self,event,output_port,dst_ip):
        event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=output_port),
                                              priority=1,
                                              match=of.ofp_match(dl_type=0x800,nw_dst=dst_ip)))
        event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=output_port),
                                              priority=1,
                                              match=of.ofp_match(dl_type=0x806,nw_dst=dst_ip)))
    def establish_flow_to_switch(self, event, output_port):
        event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=output_port),
                                              priority=1,
                                              match=of.ofp_match(dl_type=0x800)))
        event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=output_port),
                                              priority=1,
                                              match=of.ofp_match(dl_type=0x806)))

    #only works for 2 switches so far, shouldnt be too hard to adapt to work recursively
    def _handle_ConnectionUp(self, event):
        print("Conexion establecida con el switch %s" % event.dpid)
        # TODO rules should be parsed from a config file
        # TODO last rule
        #switch 1 implements the firewall
        if (event.dpid==1):
            print("switch configurado")
            #basic rules to make network effective
            self.establish_flow_to_hosts(event, 1, "10.0.0.1")
            self.establish_flow_to_hosts(event, 2, "10.0.0.2")
            self.establish_flow_to_switch(event, 3)
            #TODO these rules should be handled in parser
            event.connection.send(of.ofp_flow_mod(action=(),
                                                priority = 3,
                                                match=of.ofp_match(dl_type=0x800,
                                                                tp_dst=80,
                                                                nw_proto=17 or 6)))
            event.connection.send(of.ofp_flow_mod(action=(),
                                                 priority = 2,
                                             match=of.ofp_match(dl_type=0x800,
                                                                tp_dst=5001,
                                                                nw_src="10.0.0.1",
                                                                nw_proto=17)))
        if (event.dpid==2):
            self.establish_flow_to_hosts(event, 2, "10.0.0.3")
            self.establish_flow_to_hosts(event, 3, "10.0.0.4")
            self.establish_flow_to_switch(event, 1)
        #else:

        log.info("Connection UP")

    def _handle_ConnectionDown(self, event):
        log.info("Connection DOWN")

    def _handle_PortStatus(self, event):
        log.info("PortStatus")

    def _handle_FlowRemoved(self, event):
        log.info("FlowRemoved")

    def _handle_Statistics(self, event):
        log.info("Statistics")

    def _handle_Events(self, event):
        log.info("Events")

    def _handle_PacketIn(self, event):
        log.info("PacketIn")

    def _handle_ErrorIn(self, event):
        log.info("ErrorIn")

    def _handle_BarrierIn(self, event):
        log.info("BarrierIn")


def launch():
    core.registerNew(Firewall)
