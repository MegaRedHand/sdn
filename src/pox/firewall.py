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

    # forwards packets headed to dst_ip to the correct switch output_port
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

    def block_port_host_protocol(self, event, port, host, protocol):
        ip_host = self.get_ip_for_host(host)
        event.connection.send(of.ofp_flow_mod(action=(),
                                              priority=2,
                                              match=of.ofp_match(dl_type=0x800,
                                                                 tp_dst=port,
                                                                 nw_src=ip_host,
                                                                 nw_proto=protocol)))

    def block_traffic_hosts(self,event,host1,host2):
        ip_host1 = self.get_ip_for_host(host1)
        ip_host2 = self.get_ip_for_host(host2)
        event.connection.send(of.ofp_flow_mod(action=(),
                                              priority=2,
                                              match=of.ofp_match(dl_type=0x800,
                                                                 nw_src=ip_host1,
                                                                 nw_dst=ip_host2)))
        event.connection.send(of.ofp_flow_mod(action=(),
                                              priority=2,
                                              match=of.ofp_match(dl_type=0x800,
                                                                 nw_src=ip_host2,
                                                                 nw_dst=ip_host1)))
    def get_ip_for_host(self, host):
        return "10.0.0."+host
    def block_port(self,event,port):
        event.connection.send(of.ofp_flow_mod(action=(),
                                              priority=2,
                                              match=of.ofp_match(dl_type=0x800,
                                                                 tp_dst=port,
                                                                 nw_proto=17)))
        event.connection.send(of.ofp_flow_mod(action=(),
                                              priority=2,
                                              match=of.ofp_match(dl_type=0x800,
                                                                 tp_dst=port,
                                                                 nw_proto=6)))
    def parse_rules(self,event):
        f = open("rules.txt", "r")
        while True:
            line = f.readline()
            if not line:
                break
            regla = line.split()
            if len(regla) <= 0:
                break
            if regla[0] == "BLOCK_TRAFFIC":
                self.block_traffic_hosts(event,regla[1],regla[2])
            elif regla[0] == "BLOCK_PORT":
                self.block_port(event, int(regla[1]))
            elif regla[0] == "BLOCK_PORT_HOST_PROTOCOL":
                self.block_port_host_protocol(event, int(regla[1]),
                                regla[2],
                                int(regla[3]))
            else:
                continue



    def _handle_ConnectionUp(self, event):
        print("Connection established with switch %s" % event.dpid)
        #switch 1 implements the firewall
        if (event.dpid==1):
            #basic rules to make network effective
            self.establish_flow_to_hosts(event, 1, "10.0.0.1")
            self.establish_flow_to_hosts(event, 2, "10.0.0.2")
            self.establish_flow_to_switch(event, 3)
            #parses rules.txt to get rules
            self.parse_rules(event)
        #assuming switch 2 is the other end of the network
        if (event.dpid==2):
            self.establish_flow_to_hosts(event, 2, "10.0.0.3")
            self.establish_flow_to_hosts(event, 3, "10.0.0.4")
            self.establish_flow_to_switch(event, 1)
        # port 1 -> left switch, port 2 -> right switch
        #TODO add support for more switches
        #self.establish_flow_to_hosts(event, 1, "10.0.0.1")
        #self.establish_flow_to_hosts(event, 1, "10.0.0.2")
        #self.establish_flow_to_hosts(event, 2, "10.0.0.3")
        #self.establish_flow_to_hosts(event, 2, "10.0.0.4")
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
