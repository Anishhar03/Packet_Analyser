# Command Reference

This file explains every important command used in the project.

## Configure

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
```

Meaning:

- `cmake`: runs the CMake build generator.
- `-S .`: source directory is the current folder.
- `-B build`: generated build files go into `build`.
- `-DCMAKE_BUILD_TYPE=Release`: use optimized Release settings when supported by the generator.

## Build

```bash
cmake --build build --config Release
```

Meaning:

- `cmake --build`: asks CMake to compile using the configured native build system.
- `build`: the folder containing generated build files.
- `--config Release`: selects the Release configuration for multi-config tools.

## Analyze with Defaults

```bash
packet_analyzer analyze test_dpi.pcap
```

Meaning:

- `packet_analyzer`: executable name.
- `analyze`: run offline analysis mode.
- `test_dpi.pcap`: input capture file.

Outputs:

- `reports/filtered.pcap`
- `reports/analysis.json`
- `reports/flows.csv`
- `reports/dashboard.html`

## Set Filtered PCAP Output

```bash
packet_analyzer analyze test_dpi.pcap --output reports/allowed.pcap
```

Meaning:

- `--output reports/allowed.pcap`: write allowed packets to that PCAP path.

## Set JSON Report Output

```bash
packet_analyzer analyze test_dpi.pcap --json reports/analysis.json
```

Meaning:

- `--json`: chooses the JSON report destination.

JSON is best for automation, APIs, and the standalone UI.

## Set CSV Report Output

```bash
packet_analyzer analyze test_dpi.pcap --csv reports/flows.csv
```

Meaning:

- `--csv`: chooses the CSV report destination.

CSV is best for spreadsheets.

## Set HTML Report Output

```bash
packet_analyzer analyze test_dpi.pcap --html reports/dashboard.html
```

Meaning:

- `--html`: chooses the dashboard report destination.

HTML is best for direct visual inspection in a browser.

## Disable Outputs

```bash
packet_analyzer analyze test_dpi.pcap --no-pcap
packet_analyzer analyze test_dpi.pcap --no-json
packet_analyzer analyze test_dpi.pcap --no-csv
packet_analyzer analyze test_dpi.pcap --no-html
```

Meaning:

- `--no-pcap`: do not write a filtered capture.
- `--no-json`: do not write JSON.
- `--no-csv`: do not write CSV.
- `--no-html`: do not write HTML.

## Block by IP

```bash
packet_analyzer analyze test_dpi.pcap --block-ip 192.168.1.50
```

Meaning:

- Drops packets where source or destination IP is `192.168.1.50`.

## Block by Application

```bash
packet_analyzer analyze test_dpi.pcap --block-app YouTube
```

Meaning:

- Drops packets after the flow is classified as YouTube.
- Classification usually comes from TLS SNI, HTTP Host, or DNS.

## Block by Domain

```bash
packet_analyzer analyze test_dpi.pcap --block-domain "*.facebook.com"
```

Meaning:

- Drops packets when the detected domain matches the pattern.
- `*.facebook.com` matches `facebook.com` and subdomains such as `www.facebook.com`.

## Block by Port

```bash
packet_analyzer analyze test_dpi.pcap --block-port 23
```

Meaning:

- Drops packets going to destination port `23`.
- Port `23` is commonly Telnet.

## Load Rules from File

```bash
packet_analyzer analyze test_dpi.pcap --rules rules/sample_rules.txt
```

Meaning:

- Reads blocking rules from the given file.
- This is cleaner when many rules are needed.

## Limit Packet Count

```bash
packet_analyzer analyze test_dpi.pcap --max-packets 100
```

Meaning:

- Stops after reading 100 packets.
- Useful for quick debugging.

## Payload Preview

```bash
packet_analyzer analyze test_dpi.pcap --payload-preview 32
```

Meaning:

- Shows up to 32 payload bytes for the first few console preview rows.
- It does not store full payloads in the reports.

## Quiet Mode

```bash
packet_analyzer analyze test_dpi.pcap --quiet
```

Meaning:

- Reduces console output.
- Useful for CI and scripts.

## Run Tests

```bash
ctest --test-dir build --build-config Release --output-on-failure
```

Meaning:

- Runs the CMake smoke test.
- The test analyzes `test_dpi.pcap`, applies a blocking rule, and creates reports.

## Regenerate Sample PCAP

```bash
python generate_test_pcap.py
```

Meaning:

- Runs the Python script that creates `test_dpi.pcap`.
- The script generates synthetic TLS, HTTP, DNS, and blocked-IP traffic.

Use this only when you intentionally want to recreate the sample capture.
