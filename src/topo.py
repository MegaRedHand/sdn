#!/usr/bin/env python3
from mininet.topo import Topo


class XWing(Topo):
    """Topología con 2 pares de hosts unidos por n switches en cadena"""

    def __init__(self, n=2):
        Topo.__init__(self)

        switch = self.addSwitch("s1")

        self.addLink(switch, self.addHost("h1"))
        self.addLink(switch, self.addHost("h2"))

        for i in range(2, n + 1):
            next_switch = self.addSwitch(f"s{i}")
            self.addLink(switch, next_switch)
            switch = next_switch

        self.addLink(switch, self.addHost("h3"))
        self.addLink(switch, self.addHost("h4"))


topos = {"xwing": (lambda x=2: XWing(x))}
