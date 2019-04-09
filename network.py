"""
Class holding info about one essid (Network)
"""


# A network, potentially consisting of multiple APs (multiple transmitters)
from access_point import AccessPoint


class Network:
    def __init__(self, id, essid, encrypted):
        self.id = id
        self.essid = essid
        self.encrypted = encrypted
        self.aps = [AccessPoint.AllAccessPoints]

    def __str__(self):
        if self.encrypted:
            enc_string = "Yes"
        else:
            enc_string = "No "
        return " %02d  %s        %s" % (self.id, enc_string, self.essid)

    @staticmethod
    def get_header():
        return " ID  Encrypted  ESSID "
