"""
Class holding info about one BSSID (Access Point)
"""


# One physical access point (one MAC address)
from utilities import convert_mac


class AccessPoint:
    def __init__(self, network, id, bssid):
        self.bssid = bssid
        self.network = network
        self.id = id
        self.clients = []

    # Print properties of this access point
    def __str__(self):
        return " %02d  %02d         %s" % (self.id, self.network.id, convert_mac(self.bssid))

    @staticmethod
    def get_header():
        return " ID  NetworkID BSSID"
