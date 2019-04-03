"""
The main file for our program
"""

# The main function that will run on program start
import os
import re
import signal
import subprocess
import sys
import threading

from scapy.layers.dot11 import Dot11ProbeResp, Dot11Beacon, Dot11, Dot11Elt, Dot11FCS
from scapy.sendrecv import sniff

# TODO Find out when this is which
# Dot11Type = Dot11
Dot11Type = Dot11FCS

# Global used variables
aps_by_id = dict()  # Maps ID (self-assigned) to AP
aps = dict()  # Dictionary with information about all access points (by BSSID)
aps_lock = threading.Lock()  # Lock so that multiple threads do not access simultaneously
shutdown = False  # Whether the program is shutting down
sniff_thread = None  # The thread used for sniffing APs


def main():
    global iface

    require_root()

    # Capture CTRL-C
    signal.signal(signal.SIGINT, finalize)

    iface = input("Please specify the interface: ")
    set_mon_mode("monitor")
    select_ap()


# Process for having the user select which AP to attack
def select_ap():
    global sniff_thread

    sniff_thread = SniffThread()
    sniff_thread.start()
    ap_id = input("Please specify the ID of the AP that you want to attack: \n")

    sniff_thread.shutdown = True
    sniff_thread.join()

    print("You selected AP ", ap_id)


# Function meant to be ran in a separate thread that will continuously attempt to detect new access points
class SniffThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.shutdown = False

    def run(self):
        sniff(iface=iface, prn=self.packet_sniffed, stop_filter=self.check_stop, count=0)

    # Function executed when scapy has sniffed a packet
    def packet_sniffed(self, pkt):
        check_for_ap(pkt)

    # Defines whether the program should stop sniffing
    def check_stop(self, pkt):
        return self.shutdown


# Set the interface in a certain mode. Typically monitor or managed
def set_mon_mode(mode):
    bash_command("ifconfig " + iface + " down")
    bash_command("iwconfig " + iface + " mode " + mode)
    bash_command("ifconfig " + iface + " up")


# Check whether a packet tells us something new about an AP
def check_for_ap(pkt):
    global aps
    if (Dot11Beacon in pkt or Dot11ProbeResp in pkt) \
            and not pkt[Dot11Type].addr3 in aps:
        ap = dict()
        ap["ssid"] = pkt[Dot11Elt].info
        ap["bssid"] = pkt[Dot11Type].addr3
        ap["channel"] = int(ord(pkt[Dot11Elt:3].info))
        capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

        # Check for encrypted networks
        if re.search("privacy", capability):
            ap["enc"] = 'Y'
        else:
            ap["enc"] = 'N'

        # Save discovered AP
        ap["id"] = len(aps)
        aps[ap["bssid"]] = ap
        aps_by_id[ap["id"]] = ap

        print_ap(ap)


# Print properties of one access point
def print_ap(ap):
    print("%02d %02d  %s  %s %s" % (int(ap["id"]), int(ap["channel"]), ap["enc"], ap["bssid"], str(ap["ssid"])))


# Execute a bach command
def bash_command(command):
    command = command.split()
    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    output, err = p.communicate()


# Makes sure the script is ran as root
def require_root():
    if os.getuid() != 0:
        print("Please run the script as root!")
        exit()


# Executed when CTRL+C is executed
def finalize(signal, frame):
    global aps, sniff_thread, shutdown

    shutdown = True

    if sniff_thread is not None:
        sniff_thread.join()

    print("########## STATISTICS ##########")
    print("Total APs found: %d" % len(aps))
    print("Encrypted APs  : %d" % len([ap for ap in aps if ap["enc"] is "Y"]))
    print("Unencrypted APs: %d" % len([ap for ap in aps if ap["enc"] is "N"]))

    sys.exit(0)


# Run the script
if __name__ == '__main__':
    main()
