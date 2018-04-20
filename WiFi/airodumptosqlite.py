#!/usr/bin/python

import sqlite3, sys
from BeautifulSoup import BeautifulSoup 

xmlDom = BeautifulSoup( open(sys.argv[1], 'r').read() )

counter = 1
location = sys.argv[3]

connection = sqlite3.connect(sys.argv[2])

for network in xmlDom.findAll('wireless-network') :
	essid = network.find('essid').text
	if not essid:
		essid = '---hidden-essid---'
	channel = network.find('channel').text
	bssid = network.find('bssid').text
	encryption = network.find('encryption').text

	print counter, essid, channel, bssid, encryption
	
	connection.execute("insert into networks (location, essid, macaddr, channel, encryption) values (?,?,?,?,?)", (location, essid, bssid, channel, encryption))
	connection.commit()

	counter += 1 


connection.close()

