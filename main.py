"""
The main file for our program
"""


# The main function that will run on program start
import re
import subprocess

from scapy.layers.dot11 import Dot11ProbeResp, Dot11Beacon, Dot11, Dot11Elt

# Global used variables
aps = dict()  # Dictionary with information about all access points


def main():
    global iface

    iface = input("Please specify the interface")
    set_mon_mode("monitor")


# Set the interface in a certain mode. Typically monitor or managed
def set_mon_mode(mode):
    bash_command("ifconfig " + iface + " down")
    bash_command("iwconfig " + iface + " mode " + mode)
    bash_command("ifconfig " + iface + " up")


# Check whether a packet tells us something new about an AP
def check_for_ap(pkt):
    global aps

    if (Dot11Beacon in pkt or Dot11ProbeResp in pkt) \
            and not pkt[Dot11].addr3 in aps:
        ap = dict()
        ap["ssid"] = pkt[Dot11Elt].info
        ap["bssid"] = pkt[Dot11].addr3
        ap["channel"] = int(ord(pkt[Dot11Elt:3].info))
        capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

        # Check for encrypted networks
        if re.search("privacy", capability):
            ap["enc"] = 'Y'
        else:
            ap["enc"] = 'N'

        # Save discovered AP
        aps[ap["bssid"]] = ap

        print_ap(ap)


def print_ap(ap):
    print("%02d  %s  %s %s" % (int(ap["channel"]), ap["enc"], ap["bssid"], ap["ssid"]))


# Execute a bach command
def bash_command(command):
    command = command.split()
    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    output, err = p.communicate()


# Run the script
if __name__ == '__main__':
    main()
