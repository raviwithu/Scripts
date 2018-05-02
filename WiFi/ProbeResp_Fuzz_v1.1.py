#!/usr/bin/python

from boofuzz import *
import socket
import time
import createdb
import datetime

sql_file_name = "ProbeResp"
db_name = "WiFi_Fuzz_Report" + str(datetime.datetime.now().strftime("%y%m%d%H%M"))
createdb.create_db(sql_file_name, db_name)

SSID = "ATT6b39KHr"
STA_MAC = "\x5c\xcf\x7f\xaf\x23\xc9" #client mac address
AP_MAC = "\x5c\xcf\x7f\xaf\x23\xc9"
interface = 'wlan0mon'

print("Starting Fuzzing .....")

#conn = createdb.create_connection(sql_file_name)

#function for scanning target
def banner_grap(target, fuzz_data_logger, session, sock): 
    scan_time = 4 #in seconds
    #sock.recv(1024)
    #session.log("printing...")
    #session.log(sock)
    #if len(sock) >= 24: print sock[10:16]
    
    fuzz_data_logger.open_test_case(fuzz_data_logger._cur_test_case_id)
    fuzz_data_logger.open_test_step("openning test case")  
    #fuzz_data_logger.log_info(fuzz_data_logger.log_recv(data))
    #fuzz_data_logger.log_recv("davdsv")
    #fuzz_data_logger.log_send("sacdsac")
    fuzz_data_logger.log_info(s_render())
    fuzz_data_logger.log_info(fuzz_data_logger._cur_test_case_id)
    #fuzz_data_logger.log_info(fuzz_data_logger.)

    ########Code For Scanning Target##################
    #######Creating a new Socket connection #########
    target_active_flag = "Failed"
    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    rawSocket.bind((interface, 0x0003))
    pkt         = rawSocket.recvfrom(2548)[0]                #Sniff WiFi packets 
    wifi_subtype     = (ord(pkt[0]) >> 4) & 0b00001111       #Wifi_subtype
    wifi_type   = (ord(pkt[0]) >> 2) & 0b00000011            #wifi type
    t_end = time.time() + scan_time # setting time for scanning target
    #loop for 30 secs to find target probe request
    while time.time() < t_end:
        #fuzz_data_logger.log_info(" src_addr  = " + str(pkt[10:16].encode('hex')) +  " dest_addr = " + str(pkt[4:10]).encode('hex'))
        if (wifi_subtype == 4) and (wifi_type == 0) :
            fuzz_data_logger.log_info("receiving probe request... device still active")
            target_active_flag = "Passed"
    if target_active_flag == "Failed":
        fuzz_data_logger.log_fail("no probe request recieved from target for " + str(scan_time) + " seconds")
    rawSocket.close()
    conn = createdb.create_connection(sql_file_name)
    c = conn.cursor()
    c.execute("INSERT INTO " + db_name +"(test_case_id, name,Fuzz_data, status) VALUES (" \
            + fuzz_data_logger._cur_test_case_id \
            + "," \
            + fuzz_data_logger._cur_test_case_id \
            + "," \
            + s_render()\
            + "," \
            + target_active_flag)
    conn.commit()
    conn.close()

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


FuzzLoggerText(file_handle="session_report.log")
logger = FuzzLogger(fuzz_loggers=[FuzzLoggerText()])
logger.INDENT_SIZE = 2
logger.DEFAULT_TEST_CASE_ID = 'DefaultTestCase'
LOG_CHECK_FORMAT = 'Check: {0}'
logger.LOG_ERROR_FORMAT = '\x1b[41m\x1b[1mError!!!! {0}\x1b[0m'
logger.LOG_FAIL_FORMAT = '\x1b[31m\x1b[1mCheck Failed: {0}\x1b[0m'
logger.LOG_INFO_FORMAT = 'Info: {0}'
logger.LOG_PASS_FORMAT = '\x1b[32m\x1b[1mCheck OK: {0}\x1b[0m'
logger.LOG_RECV_FORMAT = '\x1b[36mReceived: {0}\x1b[0m'
logger.LOG_SEND_FORMAT = '\x1b[36mTransmitting {0} bytes: {1}\x1b[0m'
logger.TEST_CASE_FORMAT = '\x1b[33m\x1b[1mTest Case: {0}\x1b[0m'
logger.TEST_STEP_FORMAT = '\x1b[35m\x1b[1mTest Step: {0}\x1b[0m'



#session = Session(target=Target(connection=SocketConnection(host= 'wlan0mon', proto = 'raw-l2')))
target_sess=Target(connection=SocketConnection(host= 'wlan0mon', proto = 'raw-l2'))
target_sess.set_fuzz_data_logger
session = Session(target=target_sess, fuzz_data_logger = logger)



#target.procmon = instrumentation.external(post=is_alive)

#session.connect(s_get("Packets"))

#pre send
#session.set_fuzz_data_logger(ifuzz_logger.IFuzzLogger)
session.session_filename = "session.log"
session.post_send  = banner_grap
session.connect(s_get("ProbeResp_Frame"))
logger.log_info("for Logging")
#session._fuzz_data_logger.log("for Logging")
#session._fuzz_data_logger.log(target_sess.recv(2048))
#session._fuzz_data_logger.log_info(session.test_number)

#log_send("Completed...")
#log("Printing...., level = 1")
#FuzzLoggerText(file_handle = "session.log")
#session.log("dsavdsv", level = 1)
#session.fuzz()
session.fuzz_single_case(5)
print logger.failure_summary()
print logger.passed_test_cases
print logger.failed_test_cases
print logger.error_test_cases

