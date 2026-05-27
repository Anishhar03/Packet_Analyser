# Deep Packet Inspection

## Meaning

Deep Packet Inspection, or DPI, means looking beyond IP addresses and ports into visible application-layer metadata.

A simple firewall might only see:

```text
192.168.1.100 -> 142.250.185.110:443
```

DPI can sometimes add:

```text
TLS SNI: www.youtube.com
Application: YouTube
```

## What This Project Inspects

Packet Analyzer inspects:

- TLS Client Hello SNI for HTTPS domain names.
- HTTP Host headers for unencrypted HTTP.
- DNS query names.
- UDP/TCP ports for fallback classification.
- Payload text patterns that can indicate risky cleartext data.

## What This Project Does Not Decrypt

The analyzer does not decrypt HTTPS payloads. It cannot see encrypted web page content, passwords inside encrypted sessions, or private application data after the TLS handshake.

## Why TLS SNI Works

In traditional TLS, the client sends a Client Hello before the encrypted session is fully established. The Client Hello can include Server Name Indication, which tells the server what hostname the client wants.

Example:

```text
Client Hello
  Extensions
    server_name = www.youtube.com
```

The analyzer extracts that hostname and maps it to an application category.

## Limitations

DPI has limits:

- Encrypted Client Hello can hide SNI.
- Some traffic only exposes IP and port.
- QUIC has more complex framing than TCP TLS.
- A domain can be served by shared CDNs, so domain classification is sometimes approximate.
- Offline PCAP analysis can only inspect what was captured.

The project handles these limits by using layered detection: SNI first, then HTTP Host, then DNS, then port fallback.
