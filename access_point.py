"""
Class holding info about one BSSID (Access Point)
"""


# One physical access point (one MAC address)
from client import Client
from utilities import convert_mac


class AccessPoint:
    def __init__(self, network, id, bssid, channel):
        self.network = network
        self.id = id
        self.bssid = bssid
        self.channel = channel
        self.clients = [Client.AllClients]

    # Print properties of this access point
    def __str__(self):
        return " %02d  %02d       %s" % (self.id, self.channel, convert_mac(self.bssid))

    @staticmethod
    def get_header():
        return " ID  CHANNEL  BSSID"
