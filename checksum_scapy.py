from scapy.all import *

packets = rdpcap("checksum_capture.pcap")

print("IP / ICMP / TCP / UDP Checksum Validation using Scapy\n")

for pkt in packets:
    if IP in pkt:
        original_ip_checksum = pkt[IP].chksum

        pkt[IP].chksum = None
        rebuilt_ip = IP(bytes(pkt[IP]))
        calculated_ip_checksum = rebuilt_ip.chksum

        print("IP Checksum -> Original:", hex(original_ip_checksum),
              "Calculated:", hex(calculated_ip_checksum))

    if ICMP in pkt:
        original_icmp_checksum = pkt[ICMP].chksum

        pkt[ICMP].chksum = None
        rebuilt_icmp = ICMP(bytes(pkt[ICMP]))
        calculated_icmp_checksum = rebuilt_icmp.chksum

        print("ICMP Checksum -> Original:", hex(original_icmp_checksum),
              "Calculated:", hex(calculated_icmp_checksum))

    if TCP in pkt and IP in pkt:
        original_tcp_checksum = pkt[TCP].chksum

        pkt[TCP].chksum = None
        rebuilt_tcp = IP(bytes(pkt[IP]))
        calculated_tcp_checksum = rebuilt_tcp[TCP].chksum

        print("TCP Checksum -> Original:", hex(original_tcp_checksum),
              "Calculated:", hex(calculated_tcp_checksum))

    if UDP in pkt and IP in pkt:
        original_udp_checksum = pkt[UDP].chksum

        pkt[UDP].chksum = None
        rebuilt_udp = IP(bytes(pkt[IP]))
        calculated_udp_checksum = rebuilt_udp[UDP].chksum

        print("UDP Checksum -> Original:", hex(original_udp_checksum),
              "Calculated:", hex(calculated_udp_checksum))

print("\nChecksum validation completed.")
