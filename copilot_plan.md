# Copilot Development Plan — Domain Intelligence CLI (Go)

## 1. Project Overview

This project aims to build a secure, tested, gosec-evaluated, CI/CD automated Golang CLI tool that:

- Accepts a comma-separated list of domains.
- Implements and extends the functionality of https://github.com/az7rb/crt.sh/blob/main/crt_v2.sh.
- Performs:
  - Domain reachability checks
  - HTTP status inspection
  - IP resolution
  - Optional DNS (-dig) queries
  - Optional WHOIS (-whois) lookups
- Supports:
  - Text, JSON, and CSV output formats
  - Output to file
- Supports optional calls to third-party inspection services:
  - URLVoid
  - Google Safe Browsing Transparency Report
  - VirusTotal
  - Norton SafeWeb
  - ScanURL.net
- Produces multi-platform binaries for Windows, Linux, macOS (Intel & ARM).
- Includes:
  - Unit tests
  - gosec scanning
  - Linting (golangci-lint)
- GitHub Actions workflow for:
  - Test
  - Lint
  - Security
  - Build matrix
  - Release automation

## 2. Core Features and Requirements

### 2.1 Input
- CLI flag `-domains example.com,example.org`
- CLI flags:
  - `-dig`
  - `-whois`
  - `-format [text|json|csv]`
  - `-out outputfile`
  - `-providers urlvoid,vt,gSafe,norton,scanurl` (use comma-separated)

### 2.2 Certificate Transparency Enumeration
- Re-implement logic of crt_v2.sh:
  - Query crt.sh using JSON endpoint.
  - Parse certificate logs for:
    - Common names
    - SANs
    - Timestamps
    - Issuer details
  - Deduplicate hostnames.

### 2.3 Reachability Tests
- HTTP GET request with timeout.
- Detect:
  - HTTP status
  - Redirects
  - TLS errors
- Resolve IP addresses (A/AAAA).

### 2.4 Optional Features
- `-dig`: Perform DNS queries (A/AAAA/MX/TXT).
- `-whois`: Query WHOIS using a Go library.
- Third‑party provider checks (with rate-limit awareness):
  - URLVoid API
  - VirusTotal domain report API
  - Google Safe Browsing Transparency Report (scrape or API)
  - Norton SafeWeb (scrape)
  - ScanURL.net

### 2.5 Output Formats
- Text table
- JSON (detailed structured output)
- CSV (summaries)

### 2.6 jq Usage Examples
Provide documentation showing how to extract:
- All discovered subdomains
- Only IP addresses
- Only HTTP statuses
- Flattened list of third‑party reputation results

Example:

```
jq '.domains[].subdomains[]'
jq '.domains[] | {domain: .name, status: .http.status}'
jq '.domains[] | {domain: .name, ips: .ips[]}'
jq '.domains[].third_party | to_entries[]'
```

---

## 3. Project Structure

```
cmd/
  domainintel/
internal/
  crt/
  reachability/
  dns/
  whois/
  providers/
  output/
tests/
```

---

## 4. Development Phases

### Phase 1 — Scaffolding
- Initialize Go module.
- Add Cobra or urfave/cli.
- Implement basic domain ingestion.

### Phase 2 — Core Functionality
- CRT enumeration
- Reachability checks
- IP resolution

### Phase 3 — Optional Features
- DNS & WHOIS
- Third‑party provider integration

### Phase 4 — Output Formats
- Text
- JSON
- CSV
- File writing

### Phase 5 — Testing
- Unit tests for each module
- Integration tests with mock servers

### Phase 6 — Security Hardening
- gosec
- Error sanitization
- Input validation

### Phase 7 — CI/CD (GitHub Actions)
- Linting (golangci-lint)
- go test
- gosec scan
- Build matrix:
  - linux/amd64
  - linux/arm64
  - windows/amd64
  - windows/arm64
  - darwin/amd64
  - darwin/arm64
- Release automation using `softprops/action-gh-release` + `actions/upload-artifact`

---

## 5. Final Deliverables

- Fully working Go CLI binary
- Test suite
- CI/CD pipeline
- gosec-compliant code
- Multi-OS release artifacts
- Markdown documentation
- jq usage examples
