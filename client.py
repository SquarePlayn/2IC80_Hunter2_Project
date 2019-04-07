"""
Class holding info about a client BSSID
"""

# Client with it's BSSID, is associated with an access_point
class Client:
    def __init__(self, bssid, id):
        self.bssid = bssid
        self.id = id

    # Information about the client
    def __str__(self):
        message = "ID: " + str(self.id)
        message += ", BSSID: " + str(self.bssid)
        message += "."
        return message
