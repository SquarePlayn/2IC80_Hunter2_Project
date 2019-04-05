import threading

from scapy.layers.eap import EAPOL
from scapy.sendrecv import sniff


class HandshakeSniffer(threading.Thread):
    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.stop = False
        self.handshake = []

    def run(self):
        sniff(
            filter="ether proto 0x888e",
            iface=self.iface, prn=self.on_sniff, stop_filter=self.check_stop)

    def on_sniff(self, pkt):
        print("   sniffed something")
        if EAPOL in pkt:
            self.handshake.append(pkt)
            print(pkt.show())

    def check_stop(self, pkt):
        return self.stop or len(self.handshake) >= 4
