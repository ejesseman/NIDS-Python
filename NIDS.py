import sys
import datetime
import socket
import dpkt
import ipaddress
import itertools
from itertools import islice
import math
import random

#Create a list of blacklisted IP addresses from the IPsum text file
#NOTE: Included 4 random source IP addresses from file due to this being only a demonstration. You may comment out if wanted.
def BlackListIP(blacklist, srcIP):
	with open('ipsum.txt', 'r') as f:

		#Credit: https://stackoverflow.com/questions/23372086/how-would-i-read-only-the-first-word-of-each-line-of-a-text-file
		#Credit: https://www.studytonight.com/python-howtos/how-to-read-a-file-from-line-2-or-skip-the-header-row
		#Only extract the IP address, not the score and start from the seventh line.
		for line in islice(f,7,None):
			BIP = line.split(None, 1)[0]
			blacklist.append(BIP)
	
	
	#Credit: https://www.geeksforgeeks.org/python-select-random-value-from-a-list/
	#You may comment out if you want to rely solely on the IPsum list
	for i in range(4):
		RandIP = random.randrange(len(srcIP))
		blacklist.append(srcIP[RandIP])

#Create list for the source and destination IP addresses along with human-readable timestamps
def IPLists(srcIP, destIP, ts, file):
	#Credit goes to: https://dpkt.readthedocs.io/en/latest/print_packets.html
	with open(file,'rb') as p:
 
		pcap = dpkt.pcap.Reader(p)

		#Credit goes to: https://dpkt.readthedocs.io/en/latest/print_packets.html
		for timestamp, i in pcap:
			eth = dpkt.ethernet.Ethernet(i)

			if not isinstance(eth.data, dpkt.ip.IP):
				continue

			ip = eth.data

			#Filter only IPv4 Addresses, source: Generative AI
			if ipaddress.IPv4Address(ip.src) and ipaddress.IPv4Address(ip.dst):
				
				#Credit: https://dpkt.readthedocs.io/en/latest/_modules/examples/print_packets.html#inet_to_str
				srcIP.append(socket.inet_ntop(socket.AF_INET, ip.src))
				destIP.append(socket.inet_ntop(socket.AF_INET, ip.dst))
				#Credit for converting timestamp: https://stackoverflow.com/questions/44533950/python-timestamps-of-packets-using-dpkt
				ts.append(str(datetime.datetime.utcfromtimestamp(timestamp)))
			else:
				continue

#Compare the source IP list with the blacklisted IP list to find any illicit IP addresses
def FindSuspiciousIPs(IPwTime, blacklist, SusIP):
	#Credit for reading 2d lists: https://stackoverflow.com/questions/23799036/how-to-traverse-a-2d-list-in-python
	for i in range(len(IPwTime)):
		for j in range(len(blacklist)):
			if blacklist[j] == IPwTime[i][1]:
				SusIP.append(IPwTime[i])

#Format and print a log output of the illicit IP addresses
def CreateLog(SusIP):
	#Credits: https://docs.python.org/3/tutorial/inputoutput.html
	print(f'{"Date/Time":30} {"Source IP":20} {"Destination IP":10}')
	for i in range(len(SusIP)):
		print(f'{SusIP[i][0]:30} {SusIP[i][1]:20} {SusIP[i][2]:10}')

def main():
	blcklst = []
	srcIP = []
	destIP = []
	timestamp = []
	SusIP = []
	file = sys.argv[1]

	IPLists(srcIP, destIP, timestamp, file)

	BlackListIP(blcklst, srcIP)

	#Create a 2-dimensional list for the timestamps and source and destination IPS
	#Credit: https://stackoverflow.com/questions/41468116/python-how-to-combine-two-flat-lists-into-a-2d-array
	IPwTime= list(zip(timestamp, srcIP,destIP))

	#Check for any suspicious IP addresses
	FindSuspiciousIPs(IPwTime, blcklst, SusIP)

	#Format and print a log
	CreateLog(SusIP)

if __name__ == "__main__":
	main()		
