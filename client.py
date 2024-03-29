"""
Class holding info about a client BSSID
"""


# Client with it's MAC address, is associated with an access_point
class Client:

    Broadcast = None
    AllClients = None

    def __init__(self, ap, id, mac):
        self.ap = ap
        self.id = id
        self.mac = mac

    # Information about the client
    def __str__(self):
        return " %02d  %s " % (self.id, self.mac)

    @staticmethod
    def get_header():
        return " ID  MAC "


# Singleton for broadcast
Client.Broadcast = Client(None, 0, "Broadcast to all clients")
Client.AllClients = Client(None, 1, "Attack all clients separately")
