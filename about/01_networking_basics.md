# Networking Basics

## Packet

A packet is a small unit of network data. When an application sends data across a network, the data is split into packets. Each packet contains headers and sometimes application payload.

## Network Layers Used Here

Packet Analyzer focuses on these layers:

| Layer | Topic | What the project reads |
|---|---|---|
| Layer 2 | Ethernet | Source MAC, destination MAC, EtherType |
| Layer 3 | IPv4 | Source IP, destination IP, TTL, protocol |
| Layer 4 | TCP/UDP/ICMP | Ports, TCP flags, payload offset |
| Layer 7 | DNS/HTTP/TLS | DNS query, HTTP Host, TLS SNI |

## Ethernet

Ethernet is the link-layer wrapper for common local network traffic. The first 14 bytes usually contain:

- Destination MAC address.
- Source MAC address.
- EtherType.

EtherType tells the parser what comes next. `0x0800` means IPv4.

## IPv4

IPv4 carries packets between IP addresses such as `192.168.1.100` and `8.8.8.8`. Important IPv4 fields:

- Version: should be `4` for IPv4.
- IHL: Internet Header Length. This tells the parser where the transport header starts.
- Total Length: total IP packet size.
- TTL: Time To Live. Routers decrement it.
- Protocol: next protocol. Common values are `6` for TCP, `17` for UDP, and `1` for ICMP.
- Source and destination IP addresses.

## TCP

TCP is a reliable transport protocol. It uses ports to identify services. Common examples:

- `80`: HTTP.
- `443`: HTTPS/TLS.
- `22`: SSH.
- `25`: SMTP.

TCP flags describe connection state:

- `SYN`: connection start.
- `ACK`: acknowledgement.
- `PSH`: payload should be pushed to the application.
- `FIN`: graceful close.
- `RST`: reset.

## UDP

UDP is connectionless and has less overhead than TCP. It is common for:

- DNS on port `53`.
- QUIC/HTTP3 on UDP port `443`.
- NTP on port `123`.

## ICMP

ICMP is used for network control messages, such as ping. It does not use TCP or UDP ports.

## Five-Tuple

A flow is identified by five values:

```text
source IP + destination IP + source port + destination port + protocol
```

The analyzer uses the five-tuple to group packets into flows so it can say, for example, "this HTTPS flow belongs to YouTube and was blocked by an app rule."
