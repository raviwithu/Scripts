#!/usr/bin/python

import sys

from scapy.all import *

def packethandler(pkt):
    if pkt.haslayer(Dot11):
        print pkt.summary()
    else:
        print "Not an 802.11 Packet!"


sniff(iface = sys.argv[1], count = int(sys.argv[2]), prn = packethandler)


