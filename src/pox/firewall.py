#!/usr/bin/env python3
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.revent.revent import EventMixin
from pox.lib.util import dpidToStr, dpid_to_str
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os

# Add your imports here ...
log = core.getLogger()

# Add your global variables here ...
class Firewall(EventMixin):
    def __init__(self):
        super().__init__()
        self.listenTo(core.openflow)
        log.info("Enabling Firewall Module")

    def _handle_ConnectionUp(self, event):
        print("Conexion establecida con el switch %s" % event.dpid)
        event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=0),
                                             priority = 1,
                                             match=of.ofp_match(dl_type=0x800)))
        # TODO rules should be parsed from a config file
        # TODO last rule
        #switch 1 implements the firewall
        if (event.dpid==1):
            # discards packets with destination port 80
            event.connection.send(of.ofp_flow_mod(action=(),
                                                priority = 3,
                                                match=of.ofp_match(dl_type=0x800,
                                                                tp_dst=80,
                                                                nw_proto=17 or 6)))
            # discards packets using UDP from host 1 with destination port 5001
            event.connection.send(of.ofp_flow_mod(action=(),
                                                 priority = 2,
                                             match=of.ofp_match(dl_type=0x800,
                                                                tp_dst=5001,
                                                                nw_src="10.0.0.1",
                                                                nw_proto=17)))
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
