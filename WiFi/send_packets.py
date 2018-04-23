#!/usr/bin/python

 
#probe response variables
SC = 60512 #sequence number
channel = '\x0a'
RSN = '\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x01\x28\x00'
cap = 'short-slot+ESS+privacy+short-preamble'

from scapy.all import *
import time

class settings :
	
	# class variable 
	SC = 60512

	def __init__ (self, ssid, Source_MAC, Ap_MAC) :

		# ports_to_scan is an instance variable 	
		self.ssid = ssid
                self.Source_MAC = Source_MAC
                self.Ap_MAC = Ap_MAC

		
	def probe_response(self) :
                send_pkt = RadioTap(version = 0, pad= 0, len = 18, present   = "Flags+Rate+Channel+dBm_AntSignal+Antenna+b14", notdecoded= '\x00\x02\xa8\t\xa0\x00\xbf\x01\x00\x00')\
                / Dot11(subtype=5, addr1=self.Source_MAC, addr2=self.Ap_MAC, addr3=self.Source_MAC, SC=SC)\
                / Dot11ProbeResp(timestamp=time.time(), beacon_interval = 100, cap=cap)\
                / Dot11Elt(ID='SSID', info=self.ssid)\
                / Dot11Elt(ID='Rates', info='\x82\x84\x8b\x96\x0c\x12\x18$')\
                / Dot11Elt(ID='DSset', info=channel)\
                / Dot11Elt(ID='RSNinfo', info=RSN)

                send(send_pkt, count =10)
		return send_pkt.payload.info
                
	def beacon(self) :
                send_pkt = RadioTap(version = 0, pad= 0, len = 18, present   = "Flags+Rate+Channel+dBm_AntSignal+Antenna+b14", notdecoded= '\x00\x02\xa8\t\xa0\x00\xbf\x01\x00\x00')\
                        / Dot11(subtype=8, addr1=self.Source.MAC, addr2=self.Ap_MAC, addr3=self.Source_MAC, SC=SC)\
                / Dot11ProbeResp(timestamp=time.time(), beacon_interval = 100, cap=cap)\
                / Dot11Elt(ID='SSID', info=self.ssid)\
                / Dot11Elt(ID='Rates', info='\x82\x84\x8b\x96\x0c\x12\x18$')\
                / Dot11Elt(ID='DSset', info=channel)\
                / Dot11Elt(ID='RSNinfo', info=RSN)

                send(send_pkt, count =10)
		return send_pkt.payload.info
                


newScan = settings('RaviSankar2.5G','FC:C2:DE:E4:27:5C','90:1A:CA:D5:26:10' )

print "Faking probe response from AP : " + str (newScan.probe_response()) 



