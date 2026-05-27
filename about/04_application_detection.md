# Application Detection

## Detection Order

The analyzer uses this order:

1. TLS SNI.
2. HTTP Host header.
3. DNS query name.
4. QUIC or service-port fallback.

The most specific result wins. For example, a flow first seen as generic HTTPS can later become YouTube when a TLS SNI packet is found.

## TLS SNI Detection

The code checks whether the payload looks like a TLS Client Hello:

- TLS record content type is handshake.
- TLS version is in the expected range.
- Handshake type is Client Hello.

Then it walks the Client Hello extensions until it finds extension `0x0000`, the SNI extension.

## HTTP Host Detection

For unencrypted HTTP, the analyzer looks for request methods such as:

- `GET`
- `POST`
- `PUT`
- `HEAD`
- `DELETE`
- `PATCH`
- `OPTIONS`

It then extracts the `Host:` header.

## DNS Query Detection

DNS query parsing reads the question section from UDP or TCP port `53` payloads. A domain is stored as labels:

```text
3 www 6 google 3 com 0
```

The analyzer converts those labels into:

```text
www.google.com
```

## App Mapping

Domains are mapped to application names using substring patterns. Examples:

| Pattern | App |
|---|---|
| `youtube`, `ytimg`, `youtu.be` | YouTube |
| `facebook`, `fbcdn`, `meta.com` | Facebook |
| `github`, `githubusercontent` | GitHub |
| `netflix`, `nflxvideo` | Netflix |
| `tiktok`, `bytedance` | TikTok |

If a hostname is present but no specific application is recognized, the analyzer usually classifies the flow as HTTPS or HTTP.

## Risk Indicators

The analyzer also marks visible risky patterns, such as:

- HTTP Basic Authorization.
- `password=` or similar cleartext fields.
- API key or access token parameters.
- Telnet traffic.
- Cleartext HTTP payload.

These indicators do not automatically block traffic unless a matching rule is configured. They are included in JSON, CSV, and HTML reports.
