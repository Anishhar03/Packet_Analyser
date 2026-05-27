# End-to-End Workflow

This guide explains the complete flow from source code to final reports.

## 1. Install Requirements

You need:

- CMake 3.16 or newer.
- A C++17 compiler.
- Optional: Python 3 if you want to regenerate the sample PCAP.

Windows options:

- Visual Studio Build Tools with the C++ workload.
- MinGW-w64.

Linux options:

- `g++` or `clang++`.
- `cmake`.

macOS options:

- Xcode Command Line Tools.
- `cmake`.

## 2. Configure the Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
```

Meaning:

- `cmake` starts the CMake build tool.
- `-S .` says the source code is in the current directory.
- `-B build` says generated build files should go into the `build` directory.
- `-DCMAKE_BUILD_TYPE=Release` asks for an optimized build.

Result:

```text
build/
```

The `build` folder contains generated project files, not handwritten source code.

## 3. Compile the Analyzer

```bash
cmake --build build --config Release
```

Meaning:

- `--build build` compiles the project using the files generated in `build`.
- `--config Release` selects the Release executable on tools such as Visual Studio.

Result:

```text
packet_analyzer
```

or on Windows:

```text
packet_analyzer.exe
```

## 4. Run a Basic Analysis

Linux/macOS:

```bash
./build/packet_analyzer analyze test_dpi.pcap
```

Windows PowerShell:

```powershell
.\build\Release\packet_analyzer.exe analyze test_dpi.pcap
```

Meaning:

- `packet_analyzer` runs the compiled tool.
- `analyze` selects analysis mode.
- `test_dpi.pcap` is the input capture.

Default outputs:

```text
reports/filtered.pcap
reports/analysis.json
reports/flows.csv
reports/dashboard.html
```

## 5. Run with Blocking Rules

```bash
./build/packet_analyzer analyze test_dpi.pcap --rules rules/sample_rules.txt
```

Meaning:

- `--rules rules/sample_rules.txt` loads blocking rules from the sample file.
- Packets matching those rules are dropped from the filtered PCAP.
- Reports record which flows were blocked and why.

## 6. Run with Direct CLI Rules

```bash
./build/packet_analyzer analyze test_dpi.pcap \
  --block-app YouTube \
  --block-domain "*.tiktok.com" \
  --block-ip 192.168.1.50 \
  --block-port 23
```

Meaning:

- `--block-app YouTube` blocks flows classified as YouTube.
- `--block-domain "*.tiktok.com"` blocks TikTok domains and subdomains.
- `--block-ip 192.168.1.50` blocks traffic involving that IP.
- `--block-port 23` blocks traffic to destination port 23, commonly Telnet.

## 7. Open the Dashboard

Open:

```text
reports/dashboard.html
```

What it shows:

- Total packets.
- Total flows.
- Forwarded and dropped packet counts.
- TCP and UDP counts.
- Application distribution.
- Top domains.
- Searchable flow table.
- Block reasons and indicators.

## 8. Use the Standalone UI

Open:

```text
ui/index.html
```

Then choose:

```text
reports/analysis.json
```

Meaning:

- `ui/index.html` is a browser-only JSON report viewer.
- `reports/analysis.json` is the machine-readable report produced by the analyzer.

## 9. Inspect the Filtered PCAP

Open this file in Wireshark:

```text
reports/filtered.pcap
```

Meaning:

- Allowed packets are present.
- Blocked packets are removed.
- This lets you verify the effect of blocking rules visually.

## 10. Run the Smoke Test

```bash
ctest --test-dir build --build-config Release --output-on-failure
```

Meaning:

- `ctest` runs tests declared in `CMakeLists.txt`.
- `--test-dir build` tells CTest where the configured build is.
- `--build-config Release` selects the Release executable.
- `--output-on-failure` prints logs if the test fails.

The smoke test runs the analyzer against `test_dpi.pcap`, applies a YouTube blocking rule, and creates reports under the build folder.

## 11. CI Workflow

On GitHub, `.github/workflows/cmake.yml` automatically:

1. Checks out the repository.
2. Configures CMake.
3. Builds the executable.
4. Runs the smoke test.
5. Uploads generated reports as artifacts.

This proves the project works on Ubuntu, Windows, and macOS.

## 12. Full Internal Data Flow

```text
PCAP file
  -> PcapReader
  -> PacketParser
  -> Flow tracker
  -> DPI detectors
       -> TLS SNI
       -> HTTP Host
       -> DNS query
       -> Port fallback
  -> Rule engine
       -> IP rule
       -> App rule
       -> Domain rule
       -> Port rule
  -> Outputs
       -> Filtered PCAP
       -> JSON report
       -> CSV report
       -> HTML dashboard
```

## 13. Troubleshooting

If `cmake` is not found, install CMake and restart the terminal.

If the compiler is not found on Windows, install Visual Studio Build Tools with the C++ workload.

If the executable path is different, search inside the `build` folder for `packet_analyzer` or `packet_analyzer.exe`.

If no domains appear, the capture may not contain DNS, HTTP Host, or visible TLS SNI traffic.

If an app is not recognized, add or modify domain patterns in `src/types.cpp`.
