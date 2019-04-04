"""
The main file for our program
"""

# The main function that will run on program start
import os
import signal
import subprocess
import sys
import threading

from scapy.layers.dot11 import Dot11FCS

# TODO Find out when this is which
# Dot11Type = Dot11
from ap_sniffer import APSniffer

Dot11Type = Dot11FCS

# Global used variables
networks = []  # All found networks (essids)
sniff_thread = None  # The thread used for sniffing APs
selected_network = None  # The network to attack
selected_ap = None  # The access point to attack


def main():
    global iface, selected_network, selected_ap

    require_root()

    # Capture CTRL-C
    signal.signal(signal.SIGINT, finalize)

    iface = input("Please specify the interface: ")
    set_mon_mode("monitor")
    selected_network = select_network()
    selected_ap = select_ap()
    # TODO Select victim
    # TODO Capture handshake

    print("You were going to attack the following network and this specific AP:")
    print(selected_network)
    print(selected_ap)

    finalize()


# Process for having the user select which Network to attack
def select_network():
    global sniff_thread, networks, iface, Dot11Type

    print("Please specify the ID of the Network that you want to attack: \n")
    sniff_thread = APSniffer(iface, networks, Dot11Type, print_new_networks=True)
    sniff_thread.start()
    network_id = int(input())

    sniff_thread.shutdown = True
    sniff_thread.join()

    # TODO Check for wrong user input
    print("You selected AP ", network_id)
    return networks[network_id]


# Process for having the user select which AP to attack
def select_ap():
    global sniff_thread, iface, networks, Dot11Type, selected_network

    print("Please specify the ID of the AP that you want to attack: \n")
    for ap in selected_network.aps:
        print(ap)
    sniff_thread = APSniffer(iface, networks, Dot11Type, print_new_aps=True, target_network=selected_network)
    sniff_thread.start()
    ap_id = int(input())

    sniff_thread.shutdown = True
    sniff_thread.join()

    # TODO Check for wrong user input
    print("You selected AP ", ap_id)
    return selected_network.aps[ap_id]


# Clean up and shut down
def finalize():
    global sniff_thread

    if sniff_thread is not None:
        sniff_thread.join()

    set_mon_mode("managed")

    sys.exit(0)


# ---------- UTILITIES ----------

# Prints statistics about the currently captured APs
def print_ap_stats():
    global aps

    print("########## STATISTICS ##########")
    print("Total APs found: %d" % len(aps))
    print("Encrypted APs  : %d" % len([ap for ap in aps.values() if ap.enc is "Y"]))
    print("Unencrypted APs: %d" % len([ap for ap in aps.values() if ap.enc is "N"]))


# Set the interface in a certain mode. Typically monitor or managed
def set_mon_mode(mode):
    bash_command("ifconfig " + iface + " down")
    bash_command("iwconfig " + iface + " mode " + mode)
    bash_command("ifconfig " + iface + " up")


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


# Run the script
if __name__ == '__main__':
    main()
