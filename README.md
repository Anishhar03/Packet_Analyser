# Packet Analyzer

Packet Analyzer is an offline C++17 network traffic analysis and filtering tool. It reads a `.pcap` capture, parses Ethernet, IPv4, TCP, UDP, ICMP, DNS, HTTP, TLS SNI, and common application traffic, applies optional blocking rules, writes a filtered PCAP, and generates JSON, CSV, and HTML dashboard reports.

The project is intentionally dependency-light: it builds with CMake and a C++17 compiler only.

## Features

- PCAP file reader for Ethernet captures.
- Packet parser for Ethernet, IPv4, TCP, UDP, and ICMP metadata.
- Deep packet inspection for:
  - TLS Client Hello Server Name Indication.
  - HTTP Host headers.
  - DNS query names.
  - Port-based fallback for HTTPS, HTTP, DNS, QUIC, SSH, SMTP, and other services.
- Flow tracking with the five-tuple: source IP, destination IP, source port, destination port, and protocol.
- Blocking rules for IP addresses, applications, domains, and destination ports.
- Filtered PCAP output containing only allowed packets.
- JSON report for automation and integrations.
- CSV flow report for spreadsheet analysis.
- Self-contained HTML dashboard report.
- Standalone browser UI at `ui/index.html` for loading generated JSON reports.
- GitHub Actions workflow for Linux, Windows, and macOS CMake smoke tests.

## Project Layout

```text
.
|-- include/                  Header files for parser and DPI helpers
|-- src/                      C++ source files
|-- rules/                    Example blocking rules
|-- ui/                       Browser-based JSON report viewer
|-- about/                    In-depth concept documentation
|-- workflow/                 End-to-end workflow and command guide
|-- .github/workflows/        CI build and smoke test workflow
|-- CMakeLists.txt            Build configuration
|-- generate_test_pcap.py     Creates a synthetic test PCAP
|-- test_dpi.pcap             Sample traffic used by the smoke test
```

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Meaning:

- `cmake -S . -B build` configures the project from the current folder and places generated build files in `build`.
- `-DCMAKE_BUILD_TYPE=Release` requests an optimized release build for single-config generators.
- `cmake --build build --config Release` compiles the `packet_analyzer` executable.

On Windows, the executable is usually:

```text
build\Release\packet_analyzer.exe
```

On Linux/macOS, the executable is usually:

```text
build/packet_analyzer
```

## Run

Analyze the included sample capture:

```bash
./build/packet_analyzer analyze test_dpi.pcap
```

Windows PowerShell:

```powershell
.\build\Release\packet_analyzer.exe analyze test_dpi.pcap
```

Default outputs:

```text
reports/filtered.pcap
reports/analysis.json
reports/flows.csv
reports/dashboard.html
```

## Filtering Examples

Block YouTube by detected application:

```bash
./build/packet_analyzer analyze test_dpi.pcap --block-app YouTube
```

Block TikTok domains:

```bash
./build/packet_analyzer analyze test_dpi.pcap --block-domain "*.tiktok.com"
```

Use the sample rules file:

```bash
./build/packet_analyzer analyze test_dpi.pcap --rules rules/sample_rules.txt
```

Write custom output paths:

```bash
./build/packet_analyzer analyze test_dpi.pcap \
  --output reports/allowed.pcap \
  --json reports/analysis.json \
  --csv reports/flows.csv \
  --html reports/dashboard.html
```

## Browser UI

There are two UI options:

1. Open `reports/dashboard.html` after running the analyzer.
2. Open `ui/index.html`, then choose `reports/analysis.json` from the file picker.

The UI supports searching flows, filtering by verdict, viewing app distribution, checking top domains, and inspecting block reasons or risk indicators.

## Test

```bash
ctest --test-dir build --build-config Release --output-on-failure
```

Meaning:

- `ctest` runs the configured CMake tests.
- `--test-dir build` tells CTest to use the generated build folder.
- `--build-config Release` selects the Release executable on multi-config generators such as Visual Studio.
- `--output-on-failure` prints analyzer logs if the smoke test fails.

## Documentation

- Start with [about/README.md](about/README.md) for the concepts used in the project.
- Use [workflow/END_TO_END_WORKFLOW.md](workflow/END_TO_END_WORKFLOW.md) for the complete build, run, report, and CI workflow.
- Use [workflow/COMMAND_REFERENCE.md](workflow/COMMAND_REFERENCE.md) for command-by-command meanings.

## Notes

- This is an offline PCAP analyzer. It does not capture live network traffic by itself.
- TLS payload content remains encrypted. The analyzer only inspects visible metadata such as SNI, HTTP Host, DNS query names, packet headers, and ports.
- Modern encrypted Client Hello can hide SNI. In that case the analyzer falls back to ports and flow metadata.
