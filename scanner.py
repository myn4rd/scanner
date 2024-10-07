import subprocess
import re
from scapy.all import * 

def list_interface(): 
    devices = subprocess.check_output(['ifconfig'])
    decode = devices.decode('utf-8')
    replace = decode.replace(':','')
    posible = ['wlan','wlan0mon', 'wlan0', 'wlan1', 'wlan1mon', 'wlp1s0', 'wlp1s0mon']
    for linea in replace.splitlines():
        for words in linea.split(): 
            lista = []
            lista.append(words)
            for i in lista:
                for a in posible:
                    if i == a:
                        print(' ',i)

def interfaz_usar():
    print('Favor de escribir el nombre de la interfaz a usar: ')
    valor = input()
    subprocess.run(['ifconfig', f'{valor}', 'down'])
    subprocess.run(['iwconfig', f'{valor}', 'mode', 'monitor'])
    subprocess.run(['ifconfig', f'{valor}', 'up'])
    return valor     

def interfaz_no_usar():
    print('Favor de escribir el nombre de la interfaz a usar: ')
    valor = input()
    subprocess.run(['ifconfig', f'{valor}', 'down'])
    subprocess.run(['iwconfig', f'{valor}', 'mode', 'managed'])
    subprocess.run(['ifconfig', f'{valor}', 'up'])


def process_wifi_packet(packet):
      if packet.haslayer(Dot11ProbeReq) or packet.haslayer(Dot11ProbeResp) or packet.haslayer(Dot11AssoReq):
              ssid = packet.info.decode('utf-8', errors='ignore')
              bssid = packet.addr3
              if ssid and ssid not in seen_ssids and bssid.lower() != 'ff:ff:ff:ff:ff:ff':
                       seen_ssids.add(ssid)
                       print(f"[+] SSID: {ssid} ---->  BSSID: {bssid}")



list_interface()
encender_apagar = input('Desea poner en monitor o en manage mode (mo/ma): ')
if encender_apagar == 'mo':
    exec
    seen_ssids = set()
    sniff(iface=interfaz_usar(), prn=process_wifi_packet, store=0)
else:
    exec
    interfaz_no_usar()
