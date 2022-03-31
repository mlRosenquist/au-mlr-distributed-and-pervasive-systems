from threading import Thread
import pandas
import time
import os

# initialize the networks dataframe that will contain all access points nearby
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt
from scapy.sendrecv import sniff

networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto", "Measures", "Average"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)
dbm_measures = []

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        if(bssid != 'cc:46:d6:9b:5e:e0'):
            return
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto")

        dbm_measures.append(dbm_signal)
        sum = 0
        for x in dbm_measures:
            sum += x

        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto, len(dbm_measures), sum/len(dbm_measures))

def print_all():
    while True:
        os.system("clear")
        print(networks)
        time.sleep(0.5)

def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)

if __name__ == "__main__":
    # interface name, check using iwconfig
    interface = "wlp2s0mon"
    # start the thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    # start sniffing
    sniff(prn=callback, iface=interface, count=1000)

    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()