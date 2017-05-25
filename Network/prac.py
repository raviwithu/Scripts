
from scapy.all import *


pkts=rdpcap("prac_sniffer")
for pkt in pkts :
    print pkt[IP].dst
