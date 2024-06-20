# Advanced Network Packet Sniffer and Analyzer

This repository contains a comprehensive network packet sniffer and analyzer script built with Scapy. It captures network packets on a specified network interface and logs details about the packets, specifically identifying TCP, UDP, and HTTP packets.

## Features

- Captures TCP, UDP, and HTTP packets.
- Logs packet details to a file with timestamps.
- Provides packet statistics.
- Supports custom BPF filters for targeted packet capture.

## Requirements

- Python 3.x
- Scapy

## Installation

1. Clone the repository:

   git clone https://github.com/Hussein-Ibrahim043/advanced-network-packet-sniffer.git

2. Navigate to the project directory:

   cd advanced-network-packet-sniffer

3. Install the required dependencies:

   pip install -r requirements.txt

## Usage

To run the script, you need to specify the network interface to sniff on. Optionally, you can also specify the number of packets to capture and a BPF filter.

### Basic Usage

Capture packets on the `eth0` interface indefinitely:

   python packet_sniffer.py -i eth0

### Capture a Specific Number of Packets

Capture 100 packets on the `eth0` interface:

   python packet_sniffer.py -i eth0 -c 100

### Use a BPF Filter

Capture packets on the `eth0` interface with a filter to capture only TCP packets:

   python packet_sniffer.py -i eth0 -f "tcp"

## Arguments

- `-i`, `--interface`: Network interface to sniff on (required).
- `-c`, `--count`: Number of packets to capture (default: 0 for unlimited).
- `-f`, `--filter`: BPF filter for packet capture (default: no filter).

## Logging

Packet details are logged to `network_packet_log.txt` with timestamps. HTTP packet payloads are also logged if they can be decoded.

## Packet Statistics

After the capture is complete, the script will print packet statistics:

- Number of TCP packets
- Number of UDP packets
- Number of HTTP packets
- Number of other packets

## Example Output

Starting packet capture on interface eth0
Using filter: tcp
Protocol: TCP, Source IP: 192.168.1.100, Source Port: 12345, Destination IP: 192.168.1.1, Destination Port: 80
HTTP Request from 192.168.1.100:12345 to 192.168.1.1:80
GET / HTTP/1.1
Host: example.com

Packet capture complete.
Packet statistics: {'TCP': 10, 'UDP': 0, 'HTTP': 5, 'Other': 2}

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Author

- Hussein Ibrahim (https://github.com/Hussein-Ibrahim043)
