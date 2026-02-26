# ecdump - EtherCAT Network Analyzer

## Overview
`ecdump` is a command-line tool designed for analyzing EtherCAT network traffic. It can capture packets directly from a live network interface or read from existing PCAP/PCAPNG files. The tool analyzes EtherCAT frames to detect and report network anomalies, including Working Counter (WKC) errors, EtherCAT State Machine (ESM) transitions and errors, and invalid addressing.

## Installation

### Prerequisites
- [Rust toolchain](https://rustup.rs/) (Cargo)
- `libpcap` development headers (for Linux/macOS) or Npcap/WinPcap (for Windows).
  - Ubuntu/Debian: `sudo apt install libpcap-dev`
  - macOS: `brew install libpcap`

### Build from Source
Clone the repository and build the project using Cargo:

```bash
git clone <repository-url>
cd ecdump
cargo build --release
```

The compiled binary will be available at `target/release/ecdump`. You can optionally move it to a directory in your `PATH` (e.g., `/usr/local/bin/`).

## Usage

You can run `ecdump` to analyze live traffic or inspect pre-recorded capture files. 
*Note: Capturing live traffic from a network interface usually requires administrator/root privileges.*

### Examples

**List available network interfaces:**
```bash
ecdump -D
```

**Analyze live traffic on a specific interface:**
```bash
# Basic usage (reports errors only)
sudo ecdump -i eth0

# Detailed output (reports errors and Working Counter details)
sudo ecdump -i eth0 -vv
```

**Analyze an existing PCAP/PCAPNG file:**
```bash
ecdump -f capture.pcapng
```

**Capture live traffic and save it to a PCAP file for later analysis:**
```bash
sudo ecdump -i eth0 -w output.pcap
```

### Command-Line Options

- `-i, --interface <INTERFACE>`: Set the network interface name to capture from. If not provided, the default interface will be used.
- `-f, --file <FILE>`: Set the input PCAP/PCAPNG file path. Cannot be used simultaneously with `-i`.
- `-w, --write <FILE>`: Set the output file path to save captured packets.
- `-D, --list-interfaces`: Show available network interfaces along with their operational state.
- `-v, --verbose`: Enable verbose reporting. Can be used multiple times (e.g., `-vv`) for increased verbosity.
- `-h, --help`: Print help information.
- `-V, --version`: Print version information.