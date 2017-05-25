#!/usr/bin/env python

#Importing the logging module

import logging
from scapy.all import *


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

subprocess.call(["ifconfig", "eth0", "promisc"], stdout = None, stderr = None, shell = False)

#Performing the sniffing function
pkts= sniff(filter = "host 192.168.0.3", iface = "eth0", count = 30, timeout = 20)


subprocess.call(["ifconfig", "eth0", "-promisc"], stdout = None, stderr = None, shell = False)
wrpcap("prac_sniffer",pkts)

for pkt in pkts :
    print pkt


print str(pkts.summary()) + " "

print"\nDone Done\n"
