# PCAP and Packet Parsing

## PCAP

PCAP is a file format for captured network traffic. Tools such as Wireshark and tcpdump can create PCAP files.

A classic PCAP file has:

```text
global header
packet header + packet bytes
packet header + packet bytes
...
```

## Global Header

The global header appears once at the start of the file. It contains:

- Magic number: identifies the file as PCAP and indicates byte order.
- Version: usually `2.4`.
- Snaplen: maximum captured packet length.
- Link type: `1` means Ethernet.

Packet Analyzer expects Ethernet PCAPs because the parser starts with an Ethernet header.

## Packet Header

Each packet has a 16-byte packet header containing:

- Timestamp seconds.
- Timestamp microseconds.
- Included length: how many bytes are saved in the file.
- Original length: how long the packet was on the network.

## Packet Bytes

The packet bytes are the real network frame. For Ethernet IPv4 TCP traffic, the nesting usually looks like this:

```text
Ethernet header
  IPv4 header
    TCP header
      Application payload
```

## Parsing Process

The analyzer follows this order:

1. Read the PCAP global header.
2. Read one packet header.
3. Read the packet bytes.
4. Parse Ethernet.
5. If EtherType is IPv4, parse IPv4.
6. If protocol is TCP or UDP, parse the transport header.
7. Calculate the payload pointer and payload length.
8. Send the parsed packet to the DPI and rule logic.

## Why Offsets Matter

Headers can vary in size:

- IPv4 headers are 20 to 60 bytes.
- TCP headers are 20 to 60 bytes.

The parser reads header length fields instead of assuming every packet has a fixed layout. This is what lets it find the application payload correctly.
