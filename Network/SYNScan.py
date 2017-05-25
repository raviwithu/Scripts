#!/usr/bin/env python


import logging


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)


from scapy.all import *


target = '192.168.0.3'


ans, unans = sr(IP(dst = target) / TCP(sport = RandShort(), dport = [111, 135, 22], flags = "S"), timeout = 5)


for sent, received in ans:
	if received.haslayer(TCP) and str(received[TCP].flags) == "18":
        print str(sent[TCP].dport) + " is OPEN!"
    elif received.haslayer(TCP) and str(received[TCP].flags) == "20":
        print str(sent[TCP].dport) + " is closed!"
	elif received.haslayer(ICMP) and str(received[ICMP].type) == "3":
		print str(sent[TCP].dport) + " is filtered!"


for sent in unans:
    print str(sent[TCP].dport) + " is filtered!"