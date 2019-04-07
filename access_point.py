"""
Class holding info about one BSSID (Access Point)
"""


# One physical access point (one MAC address)
class AccessPoint:
    def __init__(self, network, id, bssid):
        self.bssid = bssid
        self.network = network
        self.id = id
        self.clients = []

    # Print properties of this access point
    def __str__(self):
        message = "ID: " + str(self.id)
        message += ", NetworkID: " + str(self.network.id)
        message += ", BSSID: " + str(self.bssid)
        message += "."
        return message
