# sniffer.py
#/syprian-junior/scapy-env/bin/sniffer.py
from scapy.all import *
from scapy.layers import http
import argparse
import signal
import sys


def signal_handler(sig, frame):
    print("\nSniffer stopped by user. Exiting...")
    sys.exit(0)


def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        protocol = protocol_map.get(proto, str(proto))

        print(f"\n[+] Packet: {src_ip} -> {dst_ip} | Protocol: {protocol}")

        if packet.haslayer(TCP):
            print(f"    TCP - Source Port: {packet[TCP].sport} -> Dest Port: {packet[TCP].dport}")
            print(f"    Flags: {packet[TCP].flags}")

        elif packet.haslayer(UDP):
            print(f"    UDP - Source Port: {packet[UDP].sport} -> Dest Port: {packet[UDP].dport}")

        if packet.haslayer(http.HTTPRequest):
            http_layer = packet.getlayer(http.HTTPRequest)
            print(f"    HTTP Request: {http_layer.Method.decode()} {http_layer.Host.decode()}{http_layer.Path.decode()}")

            if packet.haslayer(Raw):
                load = packet[Raw].load
                print(f"    Payload: {load[:100]}...")

        elif packet.haslayer(DNS):
            dns_layer = packet.getlayer(DNS)
            print(f"    DNS Query: {dns_layer.qd.qname.decode()}")


def sniff_traffic(interface, count=0):
    print(f"[*] Starting sniffer on interface {interface}")
    print("[*] Press Ctrl+C to stop...")
    sniff(iface=interface, prn=process_packet, store=0, count=count)


def get_arguments():
    parser = argparse.ArgumentParser(description="Basic Network Packet Sniffer")
    parser.add_argument("-i", "--interface", dest="interface",
                        help="Network interface to sniff on", required=True)
    parser.add_argument("-c", "--count", dest="count", type=int, default=0,
                        help="Number of packets to capture (0 for unlimited)")
    return parser.parse_args()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    args = get_arguments()
    sniff_traffic(args.interface, args.count)
