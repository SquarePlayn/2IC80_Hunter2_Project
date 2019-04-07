# Function meant to be ran in a separate thread that will continuously attempt to detect new access points
import re
import threading

from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11, Dot11FCS
from scapy.sendrecv import sniff

from access_point import AccessPoint
from network import Network
from client import Client


class APSniffer(threading.Thread):
    def __init__(self, iface, networks, dot11Type, print_new_networks=False, print_new_aps=False, print_new_clients=False, target_network=None):
        super().__init__()
        self.iface = iface
        self.networks = networks
        self.dot11Type = dot11Type
        self.print_new_networks = print_new_networks
        self.print_new_aps = print_new_aps
        self.print_new_clients = print_new_clients
        self.target_network = target_network
        self.shutdown = False

    def run(self):
        sniff(iface=self.iface, prn=self.packet_sniffed, stop_filter=self.check_stop, count=0)

    # Function executed when scapy has sniffed a packet
    def packet_sniffed(self, pkt):
        if Dot11Beacon in pkt or Dot11ProbeResp in pkt:
            # This is a packet with AP info
            essid = pkt[Dot11Elt].info
            bssid = pkt[self.dot11Type].addr3
            channel = int(ord(pkt[Dot11Elt:3].info))

            capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                            {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
            if re.search("privacy", capability):
                encrypted = True
            else:
                encrypted = False

            # Find the regarding network or create if not existent
            matching_networks = [n for n in self.networks if n.essid == essid]
            if len(matching_networks) == 0:
                # No networks yet with this ESSID, create a new one
                n_id = len(self.networks)
                network = Network(n_id, essid, encrypted, channel)
                self.networks.append(network)

                # Print it if wanted
                if self.print_new_networks:
                    print(network)

            else:
                network = matching_networks[0]

            # If we are targeting one network, quit if this is another one
            if self.target_network is not None and self.target_network is not network:
                return

            # If the AP was not know yet, add it
            matching_aps = [ap for ap in network.aps if ap.bssid == bssid]
            if len(matching_aps) == 0:
                ap_id = len(network.aps)
                ap = AccessPoint(network, ap_id, bssid)
                network.aps.append(ap)

                # Print it if wanted
                if self.print_new_aps:
                    print(ap)

            if len(matching_aps) == 1:
                ap = matching_aps[0]
                if pkt[Dot11FCS].subtype == 5:
                    if pkt[Dot11FCS].addr3 == ap.bssid:
                        client_mac = pkt[Dot11FCS].addr1
                        matching_clients = [c for c in ap.clients if c.bssid == client_mac]
                        if len(matching_clients) == 0:
                            client_id = len(ap.clients)
                            client = Client(client_mac, client_id)
                            ap.clients.append(client)
                            #Print client if wanted
                            if self.print_new_clients:
                                print(client)





    # Defines whether the program should stop sniffing
    def check_stop(self, pkt):
        return self.shutdown
