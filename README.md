# network-checksum-analysis
This repository contains Python programs for analyzing network traffic and validating packet checksums using the Scapy library.

## Aim
To validate checksums of network packets captured in a PCAP file using programmatic methods.

## Tools Used
- Python 3
- Scapy
- Wireshark

## Description
The script reads a PCAP file and recalculates checksum values for the following protocols:
- IP
- TCP
- UDP
- ICMP

The recalculated checksum values are compared with the original values present in the packet headers.

Checksum mismatches may occur due to checksum offloading, where checksum computation is handled by the network interface card.

## Files
- `checksum_validation_scapy.py` – Python script for checksum validation using Scapy

## How to Run
1. Install Scapy:
   ```bash
   pip install scapy
   

