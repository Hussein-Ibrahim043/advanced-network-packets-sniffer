import argparse
from scapy.all import sniff, TCP, IP, UDP, Raw
import logging
from datetime import datetime

# Setup logging to save all packet details to a file
logging.basicConfig(filename="network_packet_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# Packet statistics
packet_count = {
    'TCP': 0,
    'UDP': 0,
    'HTTP': 0,
    'Other': 0
}

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = 'Other'
        src_port = None
        dst_port = None

        # Check for TCP packets
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = 'TCP'
            packet_count['TCP'] += 1

            # Check for HTTP packets
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                if packet.haslayer(Raw):
                    http_payload = packet[Raw].load
                    try:
                        http_payload_decoded = http_payload.decode('utf-8')
                        if packet[TCP].dport == 80:
                            direction = 'Request'
                        else:
                            direction = 'Response'

                        log_message = (f'HTTP {direction} from {ip_src}:{src_port} to {ip_dst}:{dst_port}\n'
                                       f'{http_payload_decoded}')
                        print(log_message)
                        logging.info(log_message)
                        packet_count['HTTP'] += 1
                        return  # HTTP packet processed, skip the generic logging
                    except UnicodeDecodeError:
                        pass
        
        # Check for UDP packets
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = 'UDP'
            packet_count['UDP'] += 1

        # Log other packets
        else:
            packet_count['Other'] += 1

        # Log packet details
        log_message = (f'Protocol: {protocol}, Source IP: {ip_src}, Source Port: {src_port}, '
                       f'Destination IP: {ip_dst}, Destination Port: {dst_port}')
        print(log_message)
        logging.info(log_message)

def main():
    parser = argparse.ArgumentParser(description="A comprehensive network packet sniffer and analyzer")
    parser.add_argument("-i", "--interface", type=str, required=True, help="Network interface to sniff on")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for unlimited)")
    parser.add_argument("-f", "--filter", type=str, default="", help="BPF filter for packet capture")

    args = parser.parse_args()

    print(f"Starting packet capture on interface {args.interface}")
    if args.filter:
        print(f"Using filter: {args.filter}")

    sniff(iface=args.interface, prn=packet_callback, store=0, count=args.count, filter=args.filter)

    print("Packet capture complete.")
    print(f"Packet statistics: {packet_count}")

if __name__ == '__main__':
    main()