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

    # Print properties of this access point
    def __str__(self):
        message = "ID: " + str(self.id)
        message += ", NetworkID: " + str(self.network.id)
        message += ", BSSID: " + str(convert_mac(self.bssid))
        message += "."
        return message
