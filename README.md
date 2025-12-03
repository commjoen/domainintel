# domainintel

A command-line reconnaissance tool for gathering comprehensive intelligence about domains.

## Overview

domainintel automates the process of discovering subdomains through Certificate Transparency logs, checking their availability, resolving IP addresses, and validating TLS certificates — all from a single command.

## Features

- **Certificate Transparency Enumeration**: Discovers subdomains through CT logs (crt.sh)
- **HTTP/HTTPS Reachability Checks**: Tests connectivity with status codes and response times
- **IP Address Resolution**: Resolves A and AAAA records
- **TLS Certificate Validation**: Checks certificate validity and expiration
- **Multiple Output Formats**: Text tables, JSON, and CSV
- **Concurrent Processing**: Configurable worker pool for faster scans

## Installation

### From Source

Requires Go 1.21 or later.

```bash
# Clone the repository
git clone https://github.com/commjoen/domainintel.git
cd domainintel

# Build the binary
make build

# Or build directly with Go
go build -o domainintel ./cmd/domainintel
```

### Pre-built Binaries

Download pre-built binaries from the [Releases](https://github.com/commjoen/domainintel/releases) page.

## Usage

### Basic Usage

```bash
# Basic subdomain enumeration
domainintel --domains example.com

# Multiple domains
domainintel --domains example.com,example.org
```

### Output Formats

```bash
# Text output (default)
domainintel --domains example.com --format text

# JSON output (great for jq processing)
domainintel --domains example.com --format json

# CSV output
domainintel --domains example.com --format csv

# Save to file
domainintel --domains example.com --format csv --out results.csv
```

### Advanced Options

```bash
# Increase timeout for slow networks
domainintel --domains example.com --timeout 30s

# Increase concurrency for faster scans
domainintel --domains example.com --concurrent 20

# Verbose output for debugging
domainintel --domains example.com --verbose
```

### jq Examples

```bash
# Extract all discovered subdomains
domainintel --domains example.com --format json | jq -r '.domains[].subdomains[].hostname'

# Get subdomain and status pairs
domainintel --domains example.com --format json | jq '.domains[].subdomains[] | {hostname, status: .https.status}'

# List all unique IP addresses
domainintel --domains example.com --format json | jq -r '.domains[].subdomains[].ips[]' | sort -u

# Find subdomains with TLS issues
domainintel --domains example.com --format json | jq '.domains[].subdomains[] | select(.tls.valid == false)'

# Export reachable subdomains only
domainintel --domains example.com --format json | jq -r '.domains[].subdomains[] | select(.reachable == true) | .hostname'
```

## CLI Flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--domains` | `-d` | string | (required) | Comma-separated list of target domains |
| `--format` | `-f` | string | `text` | Output format: `text`, `json`, or `csv` |
| `--out` | `-o` | string | stdout | Write output to file path |
| `--timeout` | `-t` | duration | `10s` | HTTP request timeout |
| `--concurrent` | `-c` | int | `10` | Maximum concurrent requests |
| `--verbose` | `-v` | bool | `false` | Enable verbose logging |

## Development

### Prerequisites

- Go 1.21 or later
- golangci-lint (optional, for linting)
- gosec (optional, for security scanning)

### Build Commands

```bash
# Build
make build

# Run tests
make test

# Run tests with coverage
make test-coverage

# Run linter
make lint

# Run security scan
make security

# Build for all platforms
make build-all

# Clean build artifacts
make clean
```

### Project Structure

```
domainintel/
├── cmd/domainintel/     # CLI entry point
├── internal/
│   ├── crt/             # Certificate Transparency queries
│   ├── reachability/    # HTTP checks and IP resolution
│   └── output/          # Output formatters
├── pkg/models/          # Shared data structures
├── tests/               # Integration tests
├── Makefile             # Build automation
└── README.md            # This file
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
