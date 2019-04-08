import random
import threading
import time

from utilities import set_channel


class ChannelHopper(threading.Thread):
    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.stop = False
        self.channel = random.randrange(1, 12)

    def run(self):
        while not self.stop:
            # self.channel = random.randrange(1, 12)
            self.channel = (self.channel + 1) % 11 + 1
            set_channel(self.iface, self.channel)
            time.sleep(0.15)
