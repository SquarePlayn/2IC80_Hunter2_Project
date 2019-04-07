import threading

from scapy.layers.eap import EAPOL
from scapy.sendrecv import sniff
from scapy.utils import wrpcap

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
        wrpcap('handshake.pcap', self.handshake)

    def on_sniff(self, pkt):
        print("   sniffed something")
        if EAPOL in pkt:
            self.handshake.append(pkt)

    def check_stop(self, pkt):
        return self.stop or len(self.handshake) >= 4
