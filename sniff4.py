from scapy.all import *

def sniffer(packet):
	#print(pkt.summary())   #summary()/show()FOR DISPLAYING ALL PACKETS IN YOUR NETWORK
	if packet[IP].dport == 80:
		print("\n{} -----HTTP---> {}:{}:\n{}".format(packet[IP].src,packet[IP].dst,packet[IP].dport,str(bytes(packet[TCP].payload))))
	
sniff(filter='tcp port 80', count=10, prn=sniffer) #filter is used for http and https
