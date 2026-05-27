# Reports, UI, Build, and CI

## Filtered PCAP

The filtered PCAP contains the packets that were allowed by the rule engine. You can open it in Wireshark to inspect the resulting traffic.

Default path:

```text
reports/filtered.pcap
```

## JSON Report

The JSON report is for automation. It contains:

- Summary counters.
- Rule list.
- Flow table.
- App classifications.
- Domains.
- Block reasons.
- Risk indicators.

Default path:

```text
reports/analysis.json
```

## CSV Report

The CSV report is for spreadsheets and quick sorting. Each row is a flow.

Default path:

```text
reports/flows.csv
```

## HTML Dashboard

The generated HTML dashboard is self-contained. It includes:

- Summary cards.
- Application distribution bars.
- Top domains.
- Searchable and filterable flow table.

Default path:

```text
reports/dashboard.html
```

## Standalone UI

The file `ui/index.html` is a browser-based JSON report viewer. Open it in a browser, choose `reports/analysis.json`, and inspect the report interactively.

## CMake

CMake is the build system. It creates native build files for your platform:

- Visual Studio projects on Windows.
- Makefiles or Ninja files on Linux/macOS.

The main target is:

```text
packet_analyzer
```

## CTest

CTest runs the smoke test configured in `CMakeLists.txt`. The smoke test analyzes `test_dpi.pcap`, blocks YouTube, and checks that reports are produced.

## GitHub Actions

The workflow in `.github/workflows/cmake.yml` builds and tests the project on:

- Ubuntu.
- Windows.
- macOS.

It also uploads generated reports as workflow artifacts so you can inspect the dashboard from CI output.
