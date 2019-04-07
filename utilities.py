

# Makes dictionary from Wireshark data
import os
import subprocess


def initialize_mac_data():
    global mac_dict

    with open("MACdata.txt", "rb") as mac_file:
        mac_dict = dict()
        data = mac_file.readlines()
        for line in data:
            split_line = line.decode("utf-8") .split()
            if len(split_line[0]) == 8:
                mac_dict[split_line[0].lower()] = split_line[1]


# Function to look up the vendor of a certain MAC address
def convert_mac(mac):
    global mac_dict

    if mac[0:8] in mac_dict:
        return mac_dict[mac[0:8]]+mac[8:]
    else:
        return mac


# Prints statistics about the currently captured APs
def print_networks_stats(networks):
    print("")
    print("########## STATISTICS ##########")
    print("Total Networks found: %d" % len(networks))
    print("Encrypted Networks  : %d" % len([n for n in networks if n.encrypted]))
    print("Unencrypted Networks: %d" % len([n for n in networks if not n.encrypted]))


# Set the interface in a certain mode. Typically monitor or managed
def set_mon_mode(iface, mode):
    bash_command("ifconfig " + iface + " down")
    bash_command("iwconfig " + iface + " mode " + mode)
    bash_command("ifconfig " + iface + " up")


# Execute a bach command
def bash_command(command):
    command = command.split()
    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    output, err = p.communicate()


# Makes sure the script is ran as root
def require_root():
    if os.getuid() != 0:
        print("Please run the script as root!")
        exit()
