# NIDS-Python
NIDS Python

## About

A selfmade Network Intrusion Detection System (NIDS) programmed to detect an log illicit IP addresses. Using the network packet analyzer, Wireshark, all network activity is scanned and stored onto into a PCAP file. Upon creation of the file, a Python program, NIDS.py, is executed where it systematically compares IPv4 addresses from the the PCAP file with a list of IPv4 addresses from the IPsum threat inteligence feed (https://github.com/stamparm/ipsum) to capture and detect illicit IP addresses. If any matches are found, the IPv4 addresses are sent to a log file along with date and time of access.

To mitigate the risk of human error, two cronjobs were created: 
  1. Wireshark begin scan shortly after startup.
  2. Execute NIDS.py at PCAP files creation and automatically output results to a log file.

## Note
The NIDS.py program contains an optional function just to show that it works by adding extra IPv4 addresses from the users PCAP file to the ipsum.txt file. It also is set to filter for IPv4 addresses as the IP-Sum feed does not detect IPv6 addresses.
