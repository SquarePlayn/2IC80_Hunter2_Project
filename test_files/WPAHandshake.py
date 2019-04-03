import sys
from scapy import *
from scapy.layers.dot11 import *
from scapy.layers.eap import EAPOL

def getWPA(pkt):
    if EAPOL in pkt:
        allpackets.append(pkt)
        print(pkt.show())


iface = sys.argv[1]
allpackets = []
pkt = sniff(filter="ether proto 0x888e", iface=iface, count=100, prn=getWPA)
# wrpcap('sniffed.pcap', allpackets)
