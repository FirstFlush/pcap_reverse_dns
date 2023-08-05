import socket
import time
import os
import ipaddress
import argparse
import pyshark
from pyshark.capture.capture import TSharkCrashException


class PcapDNS:
    """I ran a packet capture with tshark on a server that didn't have Wireshark installed.
    I'm sure tshark probably has an option for reverse-DNS resolution but I thought this 
    would be a fun project anyways so I went ahead and wrote this. It will check all the 
    source and desination ports to see if they are common HTTP/HTTPS or TOR ports.
    
    Reverse DNS requests are sent in batches to avoid overwhelming some poor DNS server.
    This is set to a default of 100 per batch and a 1 second delay between batches.
    """
    def __init__(
            self, 
            pcap:pyshark.FileCapture, 
            batch_size:int=100, 
            delay:int=1,
        ):
        self.batch_size = batch_size
        self.web_ports = {80, 443, 8080, 8888, 9001, 9030, 9040, 9050, 9051, 9150}
        self.pcap = pcap
        self.hosts = set()
        self.resolved_hosts = []
        try:
            for packet in self.pcap:
                self.add_host(packet)
        except TSharkCrashException:
            print("\n\033[91mERROR\033[0m: TSharkCrashException")
            print("Not a valid packet capture file!\n")
            # print("\n\033[91mRed ERROR\033[0m]: TSharkCrashException\nNot a valid packet capture file!\n")
            os._exit(1)
        for i, host in enumerate(list(self.hosts)):
            if i % batch_size == 0:
                time.sleep(delay)
            resolved_host = self.resolve(host)
            self.resolved_hosts.append(resolved_host)


    def add_host(self, packet):
        """If either src or dst ports are in the list of web_ports then the corresponding
        IP is added to the self.hosts list for reverse DNS resolution.
        """
        if "TCP" not in packet:
            return

        if "IP" in packet:
            self._check_ports(packet, ip_protocol="IP")
        elif "IPV6" in packet:
            self._check_ports(packet, ip_protocol="IPV6")
        else:
            raise KeyError("Packet does not contain IPv4 or IPv6 data!")

        return


    def _check_ports(self, packet, ip_protocol:str):
        """Check if the packet["IP"] or ["IPV6"] src/dst ports are in
        the self.web_ports list if so, add the port to self.hosts
        """
        if int(packet["TCP"].srcport) in self.web_ports:
            self.hosts.add(packet[ip_protocol].src)
            # if "TLS" in packet.highest_layer:
            #     print(packet.highest_layer["TLS"])
        if int(packet["TCP"].dstport) in self.web_ports:
            self.hosts.add(packet[ip_protocol].dst)
        return
    

    def resolve(self, ip:str) -> str:
        """Resolve reverse DNS lookup and return name."""
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            try:
                name = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)[0] # port param required but irrelevant
            except socket.gaierror:
                name = ip
        else:
            try:
                name = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                name = ip
        return name


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PCAP Reverse DNS Resolver - Perform reverse DNS on HTTP, HTTPS, and TOR traffic in a pcap file."
    )
    parser.add_argument("pcap_file", help="Path to the pcap file")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Number of IP addresses to resolve in each batch. Default: 100"
    )
    parser.add_argument(
        "--time-delay",
        type=int,
        default=1,
        help="Time delay (in seconds) between each batch of DNS requests. Default: 1"
    )
    args = parser.parse_args()
    pcap_file = pyshark.FileCapture(args.pcap_file)
    pcapdns = PcapDNS(
        pcap_file,
        batch_size=args.batch_size,
        delay=args.time_delay,
    )
    print()
    for host in pcapdns.resolved_hosts:
        print(host)
    print()