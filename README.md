# PCAP Reverse DNS Resolver

![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Description

The PCAP Reverse DNS Resolver is a Python script that processes a pcap file, identifies HTTP, HTTPS, and TOR traffic, and performs reverse DNS resolution on the corresponding hosts. This script is useful for analyzing network traffic and obtaining hostnames for web requests made during the captured session. I made this script because I did a packet capture with tshark on a server that didn't have wireshark. I'm sure tshark probably has an option to resolve rDNS, but this little project was still a lot of fun.

## Features

- Identifies HTTP, HTTPS, and TOR traffic in the pcap file.
- Performs reverse DNS resolution on the identified hosts.
- Utilizes socket.gethostbyaddr() & socket.getnameinfo() for IPv4 and IPv6 address resolution, respectively.
- Supports batch processing and time delays to avoid flooding the DNS server with multiple requests.
- Outputs a list of hostnames associated with the IP addresses in the pcap.

## Requirements

- Python 3.x
- Wireshark (or Tshark) installed for capturing the pcap file (not required for offline analysis of pre-captured pcap files).

## Usage

1. Clone the repository:
```bash
git clone https://github.com/yourusername/pcap-reverse-dns-resolver.git
cd pcap-reverse-dns-resolver
```

2. Install the required dependencies: 
```bash
pip install pyshark
```

3. Execute the script with your pcap file:
```bash
python3 pcap_dns.py pcapfile.pcap
```

## License

- This project is licensed under the MIT License - see the LICENSE file for details.

## Contributions

- Contributions are welcome! If you find a bug or have a feature request, please create an issue or submit a pull request.