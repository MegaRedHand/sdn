#!/usr/bin/env python3
from pathlib import Path

import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.revent.revent import EventMixin
from pox.lib.util import dpidToStr

log = core.getLogger()
RULES_PATH = Path(__file__).absolute().parent / "rules.txt"
FILE_PARAM = "rules_file"


class Firewall(EventMixin):
    def __init__(self):
        super().__init__()
        self.listenTo(core.openflow)
        log.info("Enabling Firewall Module")
        self.rules = self.parse_rules()
        self.dpid = -1

    def parse_rules(self):
        if not RULES_PATH.exists():
            log.error(f"File {RULES_PATH} doesn't exist")
            return []

        log.info(f"Reading rules from {RULES_PATH}")
        rules = []
        rule_parsers = {
            "BLOCK_TRAFFIC": (2, Firewall.block_traffic_hosts),
            "BLOCK_PORT": (1, Firewall.block_port),
            "BLOCK_PORT_HOST_PROTOCOL": (3, Firewall.block_port_host_protocol),
        }
        with RULES_PATH.open("r") as f:
            for line in f:
                rule = line.split()
                if len(rule) < 1 or rule[0] not in rule_parsers:
                    continue

                rule, argv = rule[0], rule[1:]
                (argc, enforcer) = rule_parsers[rule]

                if len(argv) < argc:
                    print(
                        f"La regla {rule} tiene menos"
                        f"argumentos de los esperados"
                    )
                    continue

                log.info(f"Read rule '{rule}' from file")

                rules.append((enforcer, argv[:argc]))
        return rules

    # forwards packets headed to dst_ip to the correct switch output_port
    # def establish_flow_to_hosts(self, connection, output_port, dst_ip):
    #     connection.send(
    #         of.ofp_flow_mod(
    #             action=of.ofp_action_output(port=output_port),
    #             priority=0,
    #             match=of.ofp_match(
    #                 dl_type=pkt.ethernet.IP_TYPE,
    #                 nw_dst=dst_ip
    #             ),
    #         )
    #     )
    #     connection.send(
    #         of.ofp_flow_mod(
    #             action=of.ofp_action_output(port=output_port),
    #             priority=0,
    #             match=of.ofp_match(
    #                 dl_type=pkt.ethernet.ARP_TYPE,
    #                 nw_dst=dst_ip
    #             ),
    #         )
    #     )
    #
    # def establish_flow_to_switch(self, connection, output_port):
    #     connection.send(
    #         of.ofp_flow_mod(
    #             action=of.ofp_action_output(port=output_port),
    #             priority=0,
    #             match=of.ofp_match(dl_type=pkt.ethernet.IP_TYPE),
    #         )
    #     )
    #     connection.send(
    #         of.ofp_flow_mod(
    #             action=of.ofp_action_output(port=output_port),
    #             priority=0,
    #             match=of.ofp_match(dl_type=pkt.ethernet.ARP_TYPE),
    #         )
    #     )

    def block_port_host_protocol(self, connection, port, ip_host, protocol):
        log.info(
            f"Blocking packets with: port {port}, "
            f"with source ip {ip_host} and transport protocol {protocol}"
        )
        match protocol.lower():
            case "udp":
                proto = pkt.ipv4.UDP_PROTOCOL
            case "tcp":
                proto = pkt.ipv4.TCP_PROTOCOL
            case "icmp":
                proto = pkt.ipv4.ICMP_PROTOCOL
            case _:
                proto = int(protocol)

        connection.send(
            of.ofp_flow_mod(
                action=(),
                priority=0,
                match=of.ofp_match(
                    dl_type=pkt.ethernet.IP_TYPE,
                    tp_dst=int(port),
                    nw_src=ip_host,
                    nw_proto=proto,
                ),
            )
        )

    def block_traffic_hosts(self, connection, ip_host1, ip_host2):
        log.info(f"Blocking data flow between {ip_host1} and {ip_host2}")
        connection.send(
            of.ofp_flow_mod(
                action=(),
                priority=0,
                match=of.ofp_match(
                    dl_type=pkt.ethernet.IP_TYPE,
                    nw_src=ip_host1,
                    nw_dst=ip_host2,
                ),
            )
        )
        connection.send(
            of.ofp_flow_mod(
                action=(),
                priority=0,
                match=of.ofp_match(
                    dl_type=pkt.ethernet.IP_TYPE,
                    nw_src=ip_host2,
                    nw_dst=ip_host1,
                ),
            )
        )

    def block_port(self, connection, port):
        log.info(f"Blocking packets with destination port {port}")
        connection.send(
            of.ofp_flow_mod(
                action=(),
                priority=0,
                match=of.ofp_match(
                    dl_type=pkt.ethernet.IP_TYPE,
                    tp_dst=int(port),
                    nw_proto=pkt.ipv4.UDP_PROTOCOL,
                ),
            )
        )
        connection.send(
            of.ofp_flow_mod(
                action=(),
                priority=0,
                match=of.ofp_match(
                    dl_type=pkt.ethernet.IP_TYPE,
                    tp_dst=int(port),
                    nw_proto=pkt.ipv4.TCP_PROTOCOL,
                ),
            )
        )

    def configure_rules(self, connection):
        log.info(
            f"Installing firewall table entries "
            f"for switch {dpidToStr(self.dpid)}"
        )
        for enforcer, args in self.rules:
            enforcer(self, connection, *args)

    def _handle_ConnectionUp(self, event):
        print(f"Connection established with switch {dpidToStr(event.dpid)}")
        # the first connected switch implements the firewall

        if self.dpid == -1:
            self.dpid = event.dpid
            self.configure_rules(event.connection)

    def _handle_ConnectionDown(self, event):
        # log.info("Connection DOWN")
        pass

    def _handle_PortStatus(self, event):
        # log.info("PortStatus")
        pass

    def _handle_FlowRemoved(self, event):
        # log.info("FlowRemoved")
        pass

    def _handle_Statistics(self, event):
        # log.info("Statistics")
        pass

    def _handle_Events(self, event):
        # log.info("Events")
        pass

    def _handle_PacketIn(self, event):
        # log.info("PacketIn")
        pass

    def _handle_BarrierIn(self, event):
        # log.info("BarrierIn")
        pass

    def _handle_ErrorIn(self, event):
        # log.info("ErrorIn")
        pass


def launch(**kwargs):
    if FILE_PARAM in kwargs:
        import os

        global RULES_PATH
        RULES_PATH = Path(os.getcwd()).absolute().parent / kwargs[FILE_PARAM]

    core.registerNew(Firewall)
