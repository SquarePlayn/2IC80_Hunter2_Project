"""
Class holding info about one essid (Network)
"""


# A network, potentially consisting of multiple APs (multiple transmitters)
class Network:
    def __init__(self, id, essid, encrypted, channel):
        self.id = id
        self.essid = essid
        self.encrypted = encrypted
        self.channel = channel
        self.aps = []

    def __str__(self):
        message = "ID: " + str(self.id)
        message += ", encrypted: " + str(self.encrypted)
        message += ", channel: " + str(self.channel)
        message += ", #aps: " + str(len(self.aps))
        message += ", ESSID: " + str(self.essid)
        message += "."
        return message
