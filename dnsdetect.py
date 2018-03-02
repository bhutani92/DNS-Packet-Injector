import sys
import argparse
import netifaces as nif
from scapy.all import *

response_dict = {}

def dns_detect(pkt):
    tcp = False
    udp = False
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dest_ip = pkt[IP].dst
        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            if pkt.haslayer(DNS) and pkt.haslayer(DNSRR) and pkt[DNS].qr == 1:
                dns_id = pkt[DNS].id
                dns_qd = pkt[DNS].qd
                dns_qname = dns_qd.qname
                if len(response_dict) != 0:
                    if dns_id in response_dict:
                        data = response_dict[dns_id]
                        if data[IP].src == src_ip and data[IP].dst == dest_ip and data[IP].payload != pkt[IP].payload \
                                and data[DNS].qd.qname == dns_qname \
                                and data[DNSRR].rdata != pkt[DNSRR].rdata:
                            print time.strftime("%Y-%m-%d %H:%M") + " DNS poisoning attempt"
                            print "TXID [%s] Request [%s]"%(data[DNS].id, data[DNS].qd.qname.rstrip('.'))
                            print "Answer1 ",
                            for rrcount in range(data[DNS].ancount):
                                if data[DNS].an[rrcount].type == 1:
                                    dnsrr = data[DNS].an[rrcount]
                                    print "[%s] "%dnsrr.rdata,
                            print '\b'
                            print "Answer2 ",
                            for rrcount in range(pkt[DNS].ancount):
                                if pkt[DNS].an[rrcount].type == 1:
                                    dnsrr = pkt[DNS].an[rrcount]
                                    print "[%s] "%dnsrr.rdata,
                            print '\b'
                response_dict[dns_id] = pkt

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    local_interface = nif.gateways()['default'][nif.AF_INET][1]
    parser.add_argument("-i", "--interface")
    parser.add_argument("-r", "--tracefile")
    parser.add_argument("expr", nargs='*', action="store", default='', help="BPF Filter")
    args = parser.parse_args()
    if args.tracefile != None:
        sniff(filter=str(args.expr), offline=str(args.tracefile), store=0, prn=dns_detect)
    elif args.interface != None:
        sniff(filter=str(args.expr), iface=str(args.interface), store=0, prn=dns_detect)
    else:
        sniff(filter=str(args.expr), store=0, prn=dns_detect)
