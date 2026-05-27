# Flow Tracking and Rules

## Flow Tracking

Every TCP or UDP packet belongs to a flow. Packet Analyzer uses the five-tuple:

```text
source IP, destination IP, source port, destination port, protocol
```

For each flow, the analyzer stores:

- First packet timestamp.
- Last packet timestamp.
- Source and destination endpoints.
- Protocol and service.
- Packet count.
- Byte count.
- Detected application.
- Detected domain.
- Forwarded packet count.
- Dropped packet count.
- Block reason.
- Risk indicators.

## Why Flow Tracking Matters

Application metadata may not appear in the first packet. For HTTPS, the first packet can be a TCP SYN with no payload. The SNI appears later in the TLS Client Hello. Flow tracking lets the analyzer update the flow once that information appears.

## Rule Types

Rules can block by:

| Rule | Meaning |
|---|---|
| IP | Drop traffic when source or destination IP matches |
| App | Drop traffic after the app is detected |
| Domain | Drop traffic when a detected domain matches a pattern |
| Port | Drop traffic going to a destination port |

## Domain Patterns

Domain rules support:

- Exact domain: `example.com`
- Subdomain wildcard: `*.example.com`
- Prefix wildcard: `api.*`
- Suffix wildcard: `*.com`
- Contains wildcard: `*video*`

## Rule File Format

Key-value format:

```text
block_app=YouTube
block_domain=*.tiktok.com
block_port=23
```

Section format:

```text
[blocked_ips]
192.168.1.50

[blocked_apps]
YouTube
```

## Filtering Result

If a packet is allowed, it is written to the filtered PCAP. If it is blocked, it is omitted from the filtered PCAP and counted in the reports.

Because some application metadata appears after a flow starts, early handshake packets can be forwarded before an app or domain rule becomes knowable. Once a flow is classified and matches a rule, subsequent packets in that flow are dropped.
