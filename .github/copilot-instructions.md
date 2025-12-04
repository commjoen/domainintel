# Copilot Instructions for domainintel

This file provides guidance to GitHub Copilot when working with code in this repository.

## Project Overview

domainintel is a command-line reconnaissance tool for gathering comprehensive intelligence about domains. It is written in Go and automates:

- Subdomain discovery through Certificate Transparency logs
- HTTP/HTTPS reachability checks
- IP address resolution
- TLS certificate validation
- Extended DNS queries
- WHOIS lookups
- Third-party reputation checks (VirusTotal, URLVoid)

## Project Structure

```
domainintel/
├── cmd/domainintel/     # CLI entry point (main.go)
├── internal/            # Private packages
│   ├── crt/             # Certificate Transparency queries
│   ├── dns/             # Extended DNS queries
│   ├── output/          # Output formatters (text, JSON, CSV)
│   ├── providers/       # Third-party reputation services
│   ├── reachability/    # HTTP checks and IP resolution
│   └── whois/           # WHOIS lookups
├── pkg/models/          # Shared data structures
└── tests/               # Integration tests and fixtures
```

## Development Workflow

### Build and Test

```bash
# Download dependencies
make deps

# Build the binary
make build

# Run tests
make test

# Run tests with coverage
make test-coverage

# Run linter (installs golangci-lint v2 if needed)
make lint

# Run security scan (installs gosec if needed)
make security
```

### Quick Iteration

```bash
# Build and run with example domain
make run

# Or directly
go build -o domainintel ./cmd/domainintel
./domainintel --domains example.com
```

## Coding Guidelines

### Go Version

- Requires Go 1.24+ (see go.mod for exact version)
- Use modern Go idioms and standard library

### Code Style

- Follow golangci-lint rules defined in `.golangci.yml`
- Use table-driven tests for edge cases
- Handle errors explicitly - no ignored errors in production code
- Add context to errors with `fmt.Errorf("message: %w", err)`

### Security Requirements

- All domain names must be validated against RFC 1035
- Output file paths must be sanitized to prevent directory traversal
- API keys must never be logged or committed
- All HTTPS connections require TLS 1.2 or higher
- Use context with timeouts for all network operations

### Package Conventions

- `internal/` packages are private to this module
- `pkg/models/` contains shared data structures
- Each internal package should have its own test file (`*_test.go`)

### Testing

- Unit tests alongside source files
- Integration tests in `tests/integration/`
- Test fixtures in `tests/fixtures/`
- Use mock servers for external API tests
- Run `make test` before committing

## CLI Conventions

- Use `github.com/spf13/cobra` for command-line parsing
- Required flags should be marked with `MarkFlagRequired`
- Use sensible defaults (10s timeout, 10 concurrent workers)
- Support multiple output formats: text, JSON, CSV

## Dependencies

Key dependencies (see go.mod):
- `github.com/spf13/cobra` - CLI framework
- `github.com/miekg/dns` - DNS queries
- `github.com/likexian/whois` - WHOIS lookups
- `github.com/likexian/whois-parser` - WHOIS parsing
