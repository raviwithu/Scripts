#!/usr/bin/ptyhon


from boofuzz import *
from scapy.all import *

AP_MAC = 'FC:C2:DE:E4:27:5C'
STA_MAC = '90:1A:CA:D5:26:10' 


sock = socket.socket(socket.AF_PACKET, self.proto, socket.htons(ETH_P_ALL))
sock.bind((self.wifi_iface, ETH_P_ALL))
#Defininh transport 
sess = sessions.Session(proto = "wifi", sleep_time =0, skip =0)

#Defining target
target = session.target(STA_MAC, 0)

#Defining instrumentation
#arget.procmon = instrumentation.external(post=is_alive)

#Adding listen
#sess.pre_send = listen

#adding target
sess.wifi_iface = "wlan0mon"

#Adding target to fuzzing session
sess.add_target(target)

s_initialize("Packets")
s_raw("\x00\x00\x12\x00.H\x00\x00\x00\x02\xa8\t\xa0\x00\xc7\x01\x00\x00P\x08:\x01|dV\x8f\xc8\xc0<z\x8a\xa6\x91\xd0<z\x8a\xa6\x91\xd0\x10;O\t-\rf\x00\x00\x00d\x001\x04\x00\x0fBardenHouse 2.4\x01\x08\x82\x84\x8b\x96\x0c\x12\x18$\x03\x01\x0b\x07\x06US \x01\x0b\x1e*\x01\x002\x040H`l-\x1a\xac\x01\x1b\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x04\x06\xe6G\r\x00=\x16\x0b\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00J\x0e\x14\x00\n\x00,\x01\xc8\x00\x14\x00\x05\x00\x19\x00\x7f\x08\x01\x00\x00\x00\x00\x00\x00@\xdd\x18\x00P\xf2\x02\x01\x01\x80\x00\x03\xa4\x00\x00'\xa4\x00\x00BC^\x00b2/\x00\xdd\t\x00\x03\x7f\x01\x01\x00\x00\xff\x7f0\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00\xdd\x9f\x00P\xf2\x04\x10J\x00\x01\x10\x10D\x00\x01\x02\x10;\x00\x01\x03\x10G\x00\x10\x80\xd2\xe5\x8a1pZ\xca\xab\xc0\xf0\xc6\xd7\x97-\xfa\x10!\x00\x1cAtheros Communications, Inc.\x10#\x00\x04APxx\x10$\x00\x08APxx-xxx\x10B\x00\x12Serial Number Here\x10T\x00\x08\x00\x06\x00P\xf2\x04\x00\x01\x10\x11\x00\tAtherosAP\x10\x08\x00\x02!\x0c\x10<\x00\x01\x02\x10I\x00\x06\x007*\x00\x01")

s_delim(" ")

print "Total mutations : " + str(s_num_mutations()) + "\n"

print "Hex dump mutation output"

print s_hex_dump(s_render())

#Adding test

sess.connect(s_get("Packets"))

sess.fuzz()
