#!/usr/bin/env python3
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.revent.revent import EventMixin
from pox.lib.util import dpidToStr
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
