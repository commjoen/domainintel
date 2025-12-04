# domainintel

[![CI](https://github.com/commjoen/domainintel/workflows/CI/badge.svg)](https://github.com/commjoen/domainintel/actions/workflows/ci.yml)
[![Release](https://github.com/commjoen/domainintel/workflows/Release/badge.svg)](https://github.com/commjoen/domainintel/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub release](https://img.shields.io/github/v/release/commjoen/domainintel)](https://github.com/commjoen/domainintel/releases)
[![GitHub downloads](https://img.shields.io/github/downloads/commjoen/domainintel/total)](https://github.com/commjoen/domainintel/releases)
[![GitHub stars](https://img.shields.io/github/stars/commjoen/domainintel)](https://github.com/commjoen/domainintel/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/commjoen/domainintel)](https://github.com/commjoen/domainintel/network/members)
[![GitHub watchers](https://img.shields.io/github/watchers/commjoen/domainintel)](https://github.com/commjoen/domainintel/watchers)

A command-line reconnaissance tool for gathering comprehensive intelligence about domains.

## Overview

domainintel automates the process of discovering subdomains through Certificate Transparency logs, checking their availability, resolving IP addresses, and validating TLS certificates — all from a single command.

## Features

- **Certificate Transparency Enumeration**: Discovers subdomains through CT logs (crt.sh)
- **HTTP/HTTPS Reachability Checks**: Tests connectivity with status codes and response times
- **IP Address Resolution**: Resolves A and AAAA records
- **TLS Certificate Validation**: Checks certificate validity and expiration
- **Extended DNS Queries**: Full DNS reconnaissance (A, AAAA, MX, TXT, NS, CNAME, SOA)
- **WHOIS Lookups**: Domain registration information with caching
- **Third-Party Reputation**: Integration with VirusTotal and URLVoid (API keys required)
- **Multiple Output Formats**: Text tables, JSON, and CSV
- **Concurrent Processing**: Configurable worker pool for faster scans
- **Security Hardened**: Input validation, path sanitization, and secure defaults

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
| `--domains` | `-d` | string | (required) | Comma-separated list of target domains (max 100) |
| `--format` | `-f` | string | `text` | Output format: `text`, `json`, or `csv` |
| `--out` | `-o` | string | stdout | Write output to file path |
| `--timeout` | `-t` | duration | `10s` | HTTP request timeout |
| `--concurrent` | `-c` | int | `10` | Maximum concurrent requests |
| `--verbose` | `-v` | bool | `false` | Enable verbose logging |
| `--progress` | `-p` | bool | `false` | Show progress bar during scan |

## Security

This tool implements several security measures:

- **Input Validation**: All domain names are validated against RFC 1035
- **Path Sanitization**: Output file paths are sanitized to prevent directory traversal
- **Domain Limit**: Maximum 100 domains per scan to prevent abuse
- **TLS 1.2+**: All HTTPS connections require TLS 1.2 or higher
- **Timeouts**: Configurable timeouts for all network operations
- **No Secrets in Logs**: Sensitive information is never logged

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
│   ├── dns/             # Extended DNS queries
│   ├── whois/           # WHOIS lookups
│   ├── providers/       # Third-party reputation services
│   ├── reachability/    # HTTP checks and IP resolution
│   └── output/          # Output formatters
├── pkg/models/          # Shared data structures
├── tests/
│   ├── integration/     # Integration tests
│   └── fixtures/        # Test fixtures
├── Makefile             # Build automation
└── README.md            # This file
```

### Test Coverage

The project maintains comprehensive test coverage:

- Unit tests for all modules
- Integration tests with mock servers
- Table-driven tests for edge cases
- Security scanning with gosec

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
