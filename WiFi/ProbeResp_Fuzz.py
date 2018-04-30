#!/usr/bin/python

from boofuzz import *
import socket
import time

SSID = "ATT6b39KHr"
STA_MAC = "\x5c\xcf\x7f\xaf\x23\xc9" #client mac address
AP_MAC = "\x5c\xcf\x7f\xaf\x23\xc9"
interface = 'wlan0mon'


#function for scanning target
def banner_grap(session):
    #sock.recv(1024)
    #session.log("printing...")
    #session.log(sock)
    #if len(sock) >= 24: print sock[10:16]
    target_active_flag = 0
    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    rawSocket.bind((interface, 0x0003))
    pkt         = rawSocket.recvfrom(2548)[0]
    wifi_subtype     = (ord(pkt[0]) >> 4) & 0b00001111
    wifi_type   = (ord(pkt[0]) >> 2) & 0b00000011
    t_end = time.time() + 30 # setting time for 30 seconds 
    #loop for 30 secs to find target probe request
    while time.time() < t_end:
        if (wifi_subtype == 4) and (wifi_type == 0) :
            #self._fuzz_data_logger.log_info("receiving probe request... device still active")
            target_active_flag = 1
    #if target_active_flag == 0:
        #self._fuzz_data_logger.log_fail("no probe request from target for 30 seconds")



#WiFi Frame
RATES   = "\x02\x04\x0B\x16\x0c\x18\x30\x48"            #Supported Rates
COUNTRYINFO     = "\x55\x53\x20\x01\x0b\x1e"                    #Country Info
ERP42   = "\x00"                                        #Non ERP preset, Use Protection, Barker preamble, Reserved
ERP47   = "\x00"                                        #ERP
XRATES  = "\x30\x48\x60\x6c"                            #Extnded Rates
CHANNEL = 3

PROBE_RESP  = "\x50"
PROBE_RESP += "\x00"
PROBE_RESP += "\x3A\x01"
PROBE_RESP += "\x00"
PROBE_RESP +=  STA_MAC                              # Destination Addres
PROBE_RESP +=  AP_MAC                               # Source Address
PROBE_RESP +=  AP_MAC                               # BSSID Addres
PROBE_RESP += "\x00\x00"                                    # Sequence Control
PROBE_RESP += "\x00\x00\x00\x00\x01\x00\x00\x00"            # Timestamp
PROBE_RESP += "\x01\x00"                                    # Beacon Interval
PROBE_RESP += "\x01\x00"                                    # Capabilities
PROBE_RESP += "\x00" + chr(len(SSID)) + SSID                # SSID
PROBE_RESP += "\x01" + chr(len(RATES)) + RATES              # RATES
#PROBE_RESP += "\x03" + "\x01" + CHANNEL                     # CHANNEL


s_initialize("ProbeResp_Frame")

############Radio header################################
s_static("\x00\x00\x12\x00.H\x00\x00\x00\x02\xa8\t\xa0\x00\xc7\x01\x00\x00")
#############802.11 probe response#######################

###Fuzzing Probe Response###
s_static("\x50")                                        # Type/Subtype: Probe Response,version, Type: Managemnt Frame
s_static("\x00")                                        # Flags
s_static("\x3A\x01")                                    # Duration ID
s_static(STA_MAC)                                       # Destination Address - without colon
s_static(AP_MAC)                                        # Source Address - without colon
s_static(AP_MAC)                                        # BSSID Address - Without colon
s_static("\x00\x00")                                    # Fragment number and Sequence Control


############802.11 Wireless  LAN ###############################

######Fixed Paramenter####################
s_qword(0x0000000010000000, fuzzable=False)             # Timestamp
s_word(0x0001, fuzzable=False)                          # Beacon Interval
s_static("\x01\x00")                                    # Capabilities - ESS, IBSS, CFP, Privacy, short preamble, PBCC, channel agility, spectrum management, short slot time, Automatic power save, DSSS-OFDM, Delayed Block Ack, Immediate Bloack Ack,

#####Tagged Parameters##################

###SSID parameter###
s_block_start("SSID")
s_static("\x00") #Tag Number
s_string("\x0a", fuzzable = False) #length
s_string(SSID, fuzzable = False) #SSID
s_block_end()
#s_repeat("SSID", 0, 1024)

###Supported Rates###
s_block_start("Rates")
s_static("\x01") #Tag Number
s_string("\x08", fuzzable = False)
s_string(RATES, size = 8, max_len=8, fuzzable = True) #Supported Rates
s_block_end()
#s_repeat("Rates", 0, 1024, 50)

###DS parameter Set###

s_block_start("Channel")
s_static("\x03") #Tag Number -Ds Parameter Set
s_string("\x01", fuzzable = False) #length
#s_string(Channel, 0, 255, max_len=255-len(Channel))
s_string("\x0b", max_len = 1, fuzzable = True) #Current Channel
s_block_end()
#s_repeat("Channel", 0, 1024, 50)

###Country Information###

s_block_start("CountryInfo")
s_static("\x07") #Tag Number - Country information
s_string("\x06", fuzzable = False) #length
s_string(COUNTRYINFO, max_len=len(COUNTRYINFO), fuzzable = True) 
s_block_end()
#s_repeat("CountryInfo", 0, 1024, 50)

###ERP42 Information###

s_block_start("ERP42")
s_static("\x2a") #Tag Number - ERP42 information
s_string("\x01") #length
s_string(ERP42, max_len=255-len(ERP42), fuzzable = True) 
s_block_end()
#s_repeat("ERP42", 0, 1024, 50)

###Extended Support Rates###

s_block_start("XRATES")
s_static("\x32") #Tag Number - XRATES
s_string("\x01") #length
s_string(XRATES, max_len=len(XRATES), fuzzable = True) 
s_block_end()
#s_repeat("ERP42", 0, 1024, 50)



###### Fuzzing Tagged Parameter###################

s_initialize("Packets")
s_string("\x00\x00\x12\x00.H\x00\x00\x00\x02\xa8\t\xa0\x00\xc7\x01\x00\x00P\x08:\x01|dV\x8f\xc8\xc0<z\x8a\xa6\x91\xd0<z\x8a\xa6\x91\xd0\x10;O\t-\rf\x00\x00\x00d\x001\x04\x00\x0fBardenHouse 2.4\x01\x08\x82\x84\x8b\x96\x0c\x12\x18$\x03\x01\x0b\x07\x06US \x01\x0b\x1e*\x01\x002\x040H`l-\x1a\xac\x01\x1b\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x04\x06\xe6G\r\x00=\x16\x0b\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00J\x0e\x14\x00\n\x00,\x01\xc8\x00\x14\x00\x05\x00\x19\x00\x7f\x08\x01\x00\x00\x00\x00\x00\x00@\xdd\x18\x00P\xf2\x02\x01\x01\x80\x00\x03\xa4\x00\x00'\xa4\x00\x00BC^\x00b2/\x00\xdd\t\x00\x03\x7f\x01\x01\x00\x00\xff\x7f0\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00\xdd\x9f\x00P\xf2\x04\x10J\x00\x01\x10\x10D\x00\x01\x02\x10;\x00\x01\x03\x10G\x00\x10\x80\xd2\xe5\x8a1pZ\xca\xab\xc0\xf0\xc6\xd7\x97-\xfa\x10!\x00\x1cAtheros Communications, Inc.\x10#\x00\x04APxx\x10$\x00\x08APxx-xxx\x10B\x00\x12Serial Number Here\x10T\x00\x08\x00\x06\x00P\xf2\x04\x00\x01\x10\x11\x00\tAtherosAP\x10\x08\x00\x02!\x0c\x10<\x00\x01\x02\x10I\x00\x06\x007*\x00\x01", fuzzable = False)
s_delim(" ", fuzzable = True)

#s_size("Packets", length = 400)
#rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
#rawSocket.bind(("wlan0mon", 0x0003))

session = Session(target=Target(connection=SocketConnection(host= 'wlan0mon', proto = 'raw-l2')))
#target.procmon = instrumentation.external(post=is_alive)

#session.connect(s_get("Packets"))

#pre send
#session.set_fuzz_data_logger(ifuzz_logger.IFuzzLogger)
session.session_filename = "session.log"
#session.post_send  = banner_grap(session)
session.connect(s_get("ProbeResp_Frame"))
session._fuzz_data_logger.log_send("for Logging")
session._fuzz_data_logger.log_info("for Logging")

#log_send("Completed...")
#log("Printing...., level = 1")
#FuzzLoggerText(file_handle = "session.log")

#session.fuzz()
session.fuzz_single_case(1)

