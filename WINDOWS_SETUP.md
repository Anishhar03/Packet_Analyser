# Windows Setup

This guide builds the current `packet_analyzer.exe` target on Windows.

## Option 1: Visual Studio Build Tools

1. Install Visual Studio 2022 Community or Visual Studio Build Tools.
2. Select the `Desktop development with C++` workload.
3. Open `Developer PowerShell for VS 2022`.
4. Move into the project folder:

```powershell
cd "C:\path\to\Packet_Analyser"
```

Meaning: changes the terminal location to the project folder.

5. Configure the build:

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
```

Meaning: asks CMake to generate Visual Studio build files in the `build` folder.

6. Compile:

```powershell
cmake --build build --config Release
```

Meaning: builds the `packet_analyzer.exe` executable.

7. Run:

```powershell
.\build\Release\packet_analyzer.exe analyze test_dpi.pcap
```

Meaning: analyzes the sample PCAP and writes reports into `reports`.

## Option 2: MSYS2 MinGW-w64

1. Install MSYS2 from the official MSYS2 website.
2. Open `MSYS2 MINGW64`.
3. Install the tools:

```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja
```

Meaning: installs the C++ compiler, CMake, and Ninja build tool.

4. Move into the project folder:

```bash
cd /c/path/to/Packet_Analyser
```

5. Configure:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
```

6. Build:

```bash
cmake --build build
```

7. Run:

```bash
./build/packet_analyzer.exe analyze test_dpi.pcap
```

## Option 3: WSL

1. Install WSL with Ubuntu.
2. Install build tools:

```bash
sudo apt update
sudo apt install -y build-essential cmake
```

3. Move into the project folder from WSL.
4. Configure:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
```

5. Build:

```bash
cmake --build build
```

6. Run:

```bash
./build/packet_analyzer analyze test_dpi.pcap
```

## Output Files

Default outputs are:

```text
reports/filtered.pcap
reports/analysis.json
reports/flows.csv
reports/dashboard.html
```

Open `reports/dashboard.html` in a browser for the visual report.

## Verify

```powershell
ctest --test-dir build --build-config Release --output-on-failure
```

Meaning: runs the sample analysis smoke test that is configured in CMake.
