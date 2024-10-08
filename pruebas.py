from scapy.all import *
import subprocess 
from colorama import Fore, init, Style 
init()

def activate():
    subprocess.run(['ifconfig', 'wlan1', 'down' ])
    subprocess.run(['iwconfig', 'wlan1', 'mode', 'monitor'])
    subprocess.run(['ifconfig', 'wlan1', 'up'])

def scann(packet): 
    if packet.haslayer(Dot11Elt):
        essid = packet.info.decode('utf-8', errors='ignore')
        bssid = packet.addr3
        if bssid and bssid not in bssid_checked and essid != '' and bssid !='ff:ff:ff:ff:ff:ff':
            bssid_checked.add(bssid)
            print(Fore.GREEN + bssid + Style.RESET_ALL,essid )
        elif essid == '' and bssid != 'ff:ff:ff:ff:ff:ff':
            if bssid not in hidden_ssid:
                hidden_ssid.add(bssid)
                print(f'hidden bssid {Fore.RED}{bssid}' + Style.RESET_ALL)


##Main 

activate()
bssid_checked = set()
hidden_ssid = set()
sniff(iface='wlan1', prn=scann, store=0)
