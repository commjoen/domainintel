# Copilot Development Plan — Domain Intelligence CLI (Go)

## 1. Project Overview

### 1.1 Purpose
**domainintel** is a command-line reconnaissance tool designed to gather comprehensive intelligence about domains. It automates the process of discovering subdomains, checking their availability, resolving IP addresses, and querying third-party reputation services — all from a single command.

### 1.2 Goals
This project aims to build a secure, tested, gosec-evaluated, CI/CD automated Golang CLI tool that:

- **Domain Input**: Accepts a comma-separated list of domains via CLI flag (e.g., `-domains example.com,example.org`).
- **Certificate Transparency Enumeration**: Implements and extends the functionality of [crt_v2.sh](https://github.com/az7rb/crt.sh/blob/main/crt_v2.sh) to discover subdomains through certificate transparency logs.
- **Core Reconnaissance**:
  - Domain reachability checks using HTTP/HTTPS requests with configurable timeouts
  - HTTP status code inspection (200, 301, 302, 404, 500, etc.)
  - IP address resolution (A and AAAA records)
  - TLS certificate validation and error detection
- **Optional Deep Analysis**:
  - `-dig`: Extended DNS queries for A, AAAA, MX, TXT, NS, and CNAME records
  - `-whois`: WHOIS lookups for domain registration information
- **Output Flexibility**:
  - Text table format for human-readable terminal output
  - JSON format for programmatic consumption and piping to tools like `jq`
  - CSV format for spreadsheet imports and data analysis
  - File output support with `-out` flag
- **Third-Party Reputation Services** (optional, rate-limit aware):
  - URLVoid — domain reputation and blacklist checks
  - Google Safe Browsing Transparency Report — malware and phishing detection
  - VirusTotal — comprehensive threat intelligence
  - Norton SafeWeb — safety ratings
  - ScanURL.net — URL scanning service
- **Cross-Platform Distribution**: Pre-compiled binaries for Windows, Linux, and macOS (Intel and ARM architectures).
- **Quality Assurance**:
  - Comprehensive unit test coverage
  - Security scanning with gosec
  - Code quality enforcement with golangci-lint
- **CI/CD Automation**:
  - Automated testing on every push
  - Linting and security scanning in pipeline
  - Multi-platform build matrix
  - Automated release creation with artifacts

## 2. Core Features and Requirements

### 2.1 Command-Line Interface

The CLI will use [Cobra](https://github.com/spf13/cobra) or [urfave/cli](https://github.com/urfave/cli) for argument parsing. All flags should have sensible defaults and clear help messages.

#### Required Flags
| Flag | Type | Description | Example |
|------|------|-------------|---------|
| `-domains` | string | Comma-separated list of target domains | `-domains example.com,example.org` |

#### Optional Flags
| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-dig` | bool | false | Enable extended DNS queries (A/AAAA/MX/TXT/NS/CNAME) |
| `-whois` | bool | false | Enable WHOIS lookups for registration data |
| `-format` | string | text | Output format: `text`, `json`, or `csv` |
| `-out` | string | stdout | Write output to specified file path |
| `-providers` | string | none | Comma-separated third-party services: `urlvoid,vt,gSafe,norton,scanurl` |
| `-timeout` | duration | 10s | HTTP request timeout |
| `-concurrent` | int | 10 | Maximum concurrent requests |
| `-verbose` | bool | false | Enable verbose logging |

#### Example Usage
```bash
# Basic subdomain enumeration
domainintel -domains example.com

# Full reconnaissance with DNS and WHOIS
domainintel -domains example.com,example.org -dig -whois

# JSON output with third-party checks
domainintel -domains example.com -format json -providers vt,urlvoid

# Save results to file
domainintel -domains example.com -format csv -out results.csv
```

### 2.2 Certificate Transparency Enumeration

Certificate Transparency (CT) logs are public records of SSL/TLS certificates. By querying these logs, we can discover subdomains that have been issued certificates.

#### Implementation Details
- **Endpoint**: Query `crt.sh` using their JSON API: `https://crt.sh/?q=%.domain.com&output=json`
- **Input Validation**: Before constructing the URL, strictly validate the domain input:
  - Must match RFC 1035 domain name format
  - Reject any input containing URL-unsafe characters
  - Sanitize and URL-encode the domain parameter
  - Prevent injection attacks by whitelisting valid domain characters (alphanumeric, hyphen, dot)
- **Data Extraction**:
  - `common_name`: The domain name in the certificate
  - `name_value`: Subject Alternative Names (SANs) — often contains additional subdomains
  - `not_before` / `not_after`: Certificate validity period
  - `issuer_name`: Certificate Authority that issued the certificate
- **Processing**:
  - Parse JSON response into structured Go types
  - Extract all hostnames from common_name and SANs
  - Deduplicate results (certificates often have overlapping SANs)
  - Filter out wildcard entries (e.g., `*.example.com`) or optionally expand them
  - Sort results alphabetically for consistent output

#### Error Handling
- Handle rate limiting from crt.sh (HTTP 429)
- Retry with exponential backoff
- Timeout after configurable duration
- Graceful handling of malformed responses

### 2.3 Reachability Tests

For each discovered subdomain, perform connectivity tests to determine if the host is alive and accessible.

#### HTTP/HTTPS Checks
- **Method**: Send HTTP GET request to both `http://` and `https://` endpoints
- **Data Collected**:
  - HTTP status code (200, 301, 302, 403, 404, 500, etc.)
  - Final URL after redirects
  - Number of redirects followed
  - Response time (latency)
  - TLS certificate validity and expiration
  - TLS version and cipher suite
- **Error Detection**:
  - Connection refused
  - Connection timeout
  - DNS resolution failure
  - TLS handshake errors (expired cert, self-signed, hostname mismatch)

#### IP Resolution
- Resolve A records (IPv4 addresses)
- Resolve AAAA records (IPv6 addresses)
- Detect CDN/WAF presence by IP ranges (Cloudflare, Akamai, etc.)

### 2.4 Optional Features

#### DNS Deep Dive (`-dig` flag)
When enabled, perform comprehensive DNS queries for each domain:

| Record Type | Information Retrieved |
|------------|----------------------|
| A | IPv4 addresses |
| AAAA | IPv6 addresses |
| MX | Mail servers with priorities |
| TXT | SPF, DKIM, DMARC records |
| NS | Authoritative nameservers |
| CNAME | Canonical name aliases |
| SOA | Start of Authority (primary NS, admin email, serial) |

**Implementation**: Use `github.com/miekg/dns` library for DNS queries.

#### WHOIS Lookups (`-whois` flag)
Query WHOIS databases to retrieve domain registration information:

- Registrar name
- Registration date
- Expiration date
- Last updated date
- Registrant information (if not privacy-protected)
- Nameservers
- Domain status (clientTransferProhibited, etc.)

**Implementation**: Use `github.com/likexian/whois` and `github.com/likexian/whois-parser` libraries.

#### Third-Party Reputation Services (`-providers` flag)
Query external services for threat intelligence. Each provider requires careful rate-limit handling.

| Provider | Method | Data Retrieved |
|----------|--------|----------------|
| **URLVoid** | API | Blacklist status, safety score, detection engines |
| **VirusTotal** | API (key required) | Detection ratio, last scan date, categories |
| **Google Safe Browsing** | Transparency Report scrape | Malware, phishing, unwanted software flags |
| **Norton SafeWeb** | Web scrape | Safety rating, threat categories |
| **ScanURL.net** | Web scrape | URL analysis, redirect chain |

> **⚠️ Legal Notice**: Web scraping may violate Terms of Service for some providers. Consider:
> - Using official APIs where available (VirusTotal, URLVoid)
> - Reviewing each provider's ToS before implementation
> - Implementing respectful rate limiting to avoid IP blocking
> - Adding disclaimer in documentation about third-party service usage

**Rate Limiting Strategy**:
- Implement per-provider rate limiters
- Use exponential backoff on 429 responses
- Queue requests to avoid bursting
- Cache results to avoid duplicate queries

### 2.5 Output Formats

#### Text Format (Default)
Human-readable table format optimized for terminal viewing:

```
Domain: example.com
================================================================================
Subdomain            IP Address       Status  TLS   Response Time
--------------------------------------------------------------------------------
www.example.com      93.184.216.34    200     ✓     120ms
mail.example.com     93.184.216.35    200     ✓     85ms
api.example.com      -                -       -     Connection refused
================================================================================
Found 3 subdomains | 2 reachable | 1 unreachable
```

#### JSON Format
Structured data for programmatic consumption:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "domains": [
    {
      "name": "example.com",
      "subdomains": [
        {
          "hostname": "www.example.com",
          "ips": ["93.184.216.34"],
          "http": {
            "status": 200,
            "redirect_chain": [],
            "response_time_ms": 120
          },
          "tls": {
            "valid": true,
            "issuer": "DigiCert Inc",
            "expires": "2024-12-31"
          },
          "dns": {
            "a": ["93.184.216.34"],
            "aaaa": [],
            "mx": [{"priority": 10, "host": "mail.example.com"}]
          },
          "third_party": {
            "virustotal": {"detected": false, "score": "0/70"},
            "urlvoid": {"detected": false, "engines": 0}
          }
        }
      ]
    }
  ],
  "summary": {
    "total_subdomains": 3,
    "reachable": 2,
    "unreachable": 1
  }
}
```

#### CSV Format
Flat data suitable for spreadsheet analysis. Unreachable hosts use empty strings for unavailable fields:

```csv
domain,subdomain,ip,status,tls_valid,response_time_ms
example.com,www.example.com,93.184.216.34,200,true,120
example.com,mail.example.com,93.184.216.35,200,true,85
example.com,api.example.com,"","","",""
```

> **Note**: Empty values are represented as empty quoted strings (`""`) to ensure proper CSV parsing across different tools.

### 2.6 jq Usage Examples

The JSON output is designed to work seamlessly with `jq` for powerful data extraction:

```bash
# Extract all discovered subdomains
domainintel -domains example.com -format json | jq -r '.domains[].subdomains[].hostname'

# Get subdomain and status pairs
domainintel -domains example.com -format json | jq '.domains[].subdomains[] | {hostname, status: .http.status}'

# List all unique IP addresses
domainintel -domains example.com -format json | jq -r '.domains[].subdomains[].ips[]' | sort -u

# Find subdomains with TLS issues
domainintel -domains example.com -format json | jq '.domains[].subdomains[] | select(.tls.valid == false)'

# Get third-party reputation summary
domainintel -domains example.com -format json -providers vt,urlvoid | jq '.domains[].subdomains[].third_party | to_entries[]'

# Export reachable subdomains only
domainintel -domains example.com -format json | jq -r '.domains[].subdomains[] | select(.http.status == 200) | .hostname'
```

---

## 3. Project Structure

The project follows standard Go project layout conventions with clear separation of concerns:

```
domainintel/
├── cmd/
│   └── domainintel/
│       └── main.go              # Application entry point, CLI setup
├── internal/
│   ├── crt/
│   │   ├── crt.go               # Certificate Transparency log queries
│   │   └── crt_test.go          # Unit tests for CRT module
│   ├── reachability/
│   │   ├── http.go              # HTTP/HTTPS connectivity checks
│   │   ├── resolver.go          # IP address resolution
│   │   └── reachability_test.go # Unit tests
│   ├── dns/
│   │   ├── dns.go               # Extended DNS record queries
│   │   └── dns_test.go          # Unit tests
│   ├── whois/
│   │   ├── whois.go             # WHOIS lookup implementation
│   │   └── whois_test.go        # Unit tests
│   ├── providers/
│   │   ├── provider.go          # Common provider interface
│   │   ├── urlvoid.go           # URLVoid integration
│   │   ├── virustotal.go        # VirusTotal integration
│   │   ├── safebrowsing.go      # Google Safe Browsing integration
│   │   ├── norton.go            # Norton SafeWeb integration
│   │   ├── scanurl.go           # ScanURL.net integration
│   │   └── providers_test.go    # Unit tests
│   ├── output/
│   │   ├── formatter.go         # Output formatting interface
│   │   ├── text.go              # Text table formatter
│   │   ├── json.go              # JSON formatter
│   │   ├── csv.go               # CSV formatter
│   │   └── output_test.go       # Unit tests
│   └── config/
│       └── config.go            # Configuration management
├── pkg/
│   └── models/
│       └── types.go             # Shared data structures
├── tests/
│   ├── integration/
│   │   └── integration_test.go  # End-to-end tests
│   └── fixtures/
│       └── mock_responses.json  # Test fixtures
├── .github/
│   └── workflows/
│       ├── ci.yml               # CI pipeline (test, lint, security)
│       └── release.yml          # Release automation
├── .golangci.yml                # Linter configuration
├── go.mod                       # Go module definition
├── go.sum                       # Dependency checksums
├── Makefile                     # Build and development commands
├── README.md                    # Project documentation
└── LICENSE                      # License file
```

### Module Responsibilities

| Module | Purpose |
|--------|---------|
| `cmd/domainintel` | CLI setup, flag parsing, orchestration |
| `internal/crt` | Query crt.sh API, parse CT log responses |
| `internal/reachability` | HTTP checks, IP resolution, TLS validation |
| `internal/dns` | Extended DNS queries (MX, TXT, NS, etc.) |
| `internal/whois` | WHOIS lookup and parsing |
| `internal/providers` | Third-party service integrations |
| `internal/output` | Format results as text, JSON, or CSV |
| `pkg/models` | Shared data structures used across modules |

---

## 4. Development Phases

### Phase 1 — Project Scaffolding (Week 1) ✅

**Objective**: Set up the project foundation with proper Go module structure and CLI framework.

**Tasks**:
- [x] Initialize Go module: `go mod init github.com/OWNER/domainintel`
- [x] Add CLI framework (Cobra recommended for subcommand support)
- [x] Implement `main.go` with basic flag parsing
- [x] Create project directory structure
- [x] Set up Makefile with common targets (`build`, `test`, `lint`, `clean`)
- [x] Add `.gitignore` for Go projects
- [x] Create initial README.md with installation instructions

**Deliverables**:
- Working CLI that accepts `-domains` flag and prints parsed domains
- Basic project structure in place
- Development environment ready

**Acceptance Criteria**:
```bash
go build -o domainintel ./cmd/domainintel
./domainintel -domains example.com,example.org
# Output: Parsed domains: [example.com example.org]
```

---

### Phase 2 — Core Functionality (Weeks 2-3) ✅

**Objective**: Implement the primary reconnaissance features.

#### 2.1 Certificate Transparency Module
- [x] Create `internal/crt/crt.go` with crt.sh API client
- [x] Implement JSON response parsing
- [x] Extract and deduplicate subdomains from common_name and SANs
- [x] Handle wildcards and filter invalid entries
- [x] Add configurable timeout and retry logic
- [x] Write unit tests with mocked HTTP responses

#### 2.2 Reachability Module
- [x] Create `internal/reachability/http.go` for HTTP/HTTPS checks
- [x] Implement status code detection
- [x] Track redirect chains
- [x] Measure response latency
- [x] Detect and report TLS errors
- [x] Create `internal/reachability/resolver.go` for IP resolution
- [x] Write unit tests

#### 2.3 Integration
- [x] Orchestrate CRT enumeration → Reachability checks pipeline
- [x] Implement concurrent processing with configurable worker pool
- [x] Add progress reporting for long-running scans

**Deliverables**:
- Functional subdomain enumeration via CT logs
- HTTP reachability and IP resolution for discovered subdomains
- Basic text output showing results

**Acceptance Criteria**:
```bash
./domainintel -domains example.com
# Output: List of subdomains with IP addresses and HTTP status codes
```

---

### Phase 3 — Optional Features (Week 4) ✅

**Objective**: Add DNS deep dive and WHOIS lookup capabilities.

#### 3.1 DNS Module (`-dig` flag)
- [x] Create `internal/dns/dns.go` using `miekg/dns` library
- [x] Implement queries for A, AAAA, MX, TXT, NS, CNAME, SOA
- [x] Parse and structure results
- [x] Handle DNS errors gracefully (NXDOMAIN, SERVFAIL)
- [x] Write unit tests

#### 3.2 WHOIS Module (`-whois` flag)
- [x] Create `internal/whois/whois.go` using `likexian/whois`
- [x] Parse WHOIS responses to extract key fields
- [x] Handle different TLD formats
- [x] Implement caching to avoid duplicate queries
- [x] Write unit tests

#### 3.3 Third-Party Provider Integration (`-providers` flag)
- [x] Define `Provider` interface in `internal/providers/provider.go`
- [x] Implement URLVoid client
- [x] Implement VirusTotal client (requires API key)
- [ ] Implement Google Safe Browsing scraper
- [ ] Implement Norton SafeWeb scraper
- [ ] Implement ScanURL.net client
- [x] Add rate limiting per provider
- [x] Write unit tests with mocked responses

**Deliverables**:
- Complete reconnaissance toolkit with all optional features
- Rate-limited third-party provider queries

**Acceptance Criteria**:
```bash
./domainintel -domains example.com -dig -whois -providers vt,urlvoid
# Output: Full reconnaissance report including DNS records, WHOIS data, and reputation scores
```

---

### Phase 4 — Output Formats (Week 5) ✅

**Objective**: Implement flexible output formatting.

#### 4.1 Output Module
- [x] Define `Formatter` interface in `internal/output/formatter.go`
- [x] Implement `internal/output/text.go` for terminal-friendly tables
- [x] Implement `internal/output/json.go` for structured JSON output
- [x] Implement `internal/output/csv.go` for spreadsheet-compatible output
- [x] Add `-out` flag for file output
- [x] Write unit tests

#### 4.2 Integration
- [x] Connect formatters to main CLI
- [x] Ensure consistent data structure across all formats
- [x] Add streaming output for large result sets

**Deliverables**:
- Three output formats (text, JSON, CSV)
- File output capability

**Acceptance Criteria**:
```bash
./domainintel -domains example.com -format json | jq '.'
./domainintel -domains example.com -format csv -out results.csv
cat results.csv
```

---

### Phase 5 — Testing (Week 6) ✅

**Objective**: Achieve comprehensive test coverage.

#### 5.1 Unit Tests
- [x] Ensure >80% code coverage for all modules
- [x] Add table-driven tests for edge cases
- [x] Mock external API calls
- [x] Test error handling paths

#### 5.2 Integration Tests
- [x] Create `tests/integration/integration_test.go`
- [x] Set up mock servers for crt.sh, WHOIS, and providers
- [x] Test end-to-end workflows
- [x] Test concurrent execution
- [x] Test large result sets

#### 5.3 Test Infrastructure
- [x] Create test fixtures in `tests/fixtures/`
- [x] Add test helper functions
- [x] Set up test coverage reporting

**Deliverables**:
- Comprehensive test suite
- >80% code coverage
- Integration tests with mock servers

**Acceptance Criteria**:
```bash
go test ./... -cover
# Output: Coverage > 80%

go test ./tests/integration/... -v
# Output: All integration tests pass
```

---

### Phase 6 — Security Hardening (Week 7) ✅

**Objective**: Ensure the codebase is secure and follows best practices.

#### 6.1 Security Scanning
- [x] Run `gosec` and fix all findings
- [x] Review for common vulnerabilities (injection, SSRF, etc.)
- [x] Validate and sanitize all user inputs
- [x] Implement proper error handling (no stack traces in output)

#### 6.2 Input Validation
- [x] Validate domain format (RFC 1035 compliance)
- [x] Sanitize file paths for `-out` flag
- [x] Validate provider names
- [x] Limit domain list size to prevent abuse

#### 6.3 Secure Coding Practices
- [x] Use constant-time comparison for sensitive operations
- [x] Avoid logging sensitive data
- [x] Set appropriate timeouts for all HTTP clients
- [x] Use TLS 1.2+ for all HTTPS connections

**Deliverables**:
- gosec-clean codebase
- Input validation for all user inputs
- Secure default configurations

**Acceptance Criteria**:
```bash
gosec ./...
# Output: No issues found

golangci-lint run
# Output: No linting errors
```

---

### Phase 7 — CI/CD Pipeline (Week 8) ✅

**Objective**: Automate testing, building, and releasing.

#### 7.1 Continuous Integration (`.github/workflows/ci.yml`)
- [x] Trigger on push and pull request
- [x] Run `go test ./...` with coverage
- [x] Run `golangci-lint`
- [x] Run `gosec` security scan
- [x] Upload coverage reports to Codecov (optional)
- [x] Cache Go modules for faster builds

#### 7.2 Build Matrix
Configure builds for all target platforms:

| OS | Architecture | Binary Name |
|----|--------------|-------------|
| Linux | amd64 | domainintel-linux-amd64 |
| Linux | arm64 | domainintel-linux-arm64 |
| Windows | amd64 | domainintel-windows-amd64.exe |
| Windows | arm64 | domainintel-windows-arm64.exe |
| macOS | amd64 (Intel) | domainintel-darwin-amd64 |
| macOS | arm64 (Apple Silicon) | domainintel-darwin-arm64 |

#### 7.3 Release Automation (`.github/workflows/release.yml`)
- [x] Trigger on tag push (e.g., `v1.0.0`)
- [x] Build all platform binaries
- [x] Create GitHub Release using `softprops/action-gh-release`
- [x] Upload binaries as release assets
- [x] Generate changelog from commits

**Deliverables**:
- Automated CI pipeline for every push/PR
- Automated release creation on tag push
- Pre-compiled binaries for all platforms

**Acceptance Criteria**:
```bash
git tag v1.0.0
git push origin v1.0.0
# GitHub Actions creates release with all binaries attached
```

---

## 5. Final Deliverables

### 5.1 Application
- **Binary**: Fully functional `domainintel` CLI tool
- **Features**: All core and optional features implemented
- **Platforms**: Pre-compiled binaries for 6 OS/architecture combinations

### 5.2 Code Quality
- **Test Suite**: Comprehensive unit and integration tests with >80% coverage
- **Security**: gosec-compliant code with no security findings
- **Linting**: golangci-lint clean with no warnings

### 5.3 CI/CD
- **CI Pipeline**: Automated testing, linting, and security scanning on every push
- **Release Pipeline**: Automated binary builds and GitHub Release creation on tags

### 5.4 Documentation
- **README.md**: Installation, usage, and examples
- **jq Examples**: Practical `jq` commands for JSON output processing
- **API Documentation**: GoDoc comments for all public functions
- **CHANGELOG.md**: Version history and notable changes

### 5.5 Release Artifacts
For each release, the following artifacts will be available:

| File | Description |
|------|-------------|
| `domainintel-linux-amd64` | Linux 64-bit Intel/AMD |
| `domainintel-linux-arm64` | Linux 64-bit ARM |
| `domainintel-darwin-amd64` | macOS Intel |
| `domainintel-darwin-arm64` | macOS Apple Silicon |
| `domainintel-windows-amd64.exe` | Windows 64-bit Intel/AMD |
| `domainintel-windows-arm64.exe` | Windows 64-bit ARM |
| `checksums.txt` | SHA256 checksums for all binaries |

---

## 6. Dependencies

### 6.1 Required Dependencies

| Package | Purpose | License |
|---------|---------|---------|
| `github.com/spf13/cobra` | CLI framework | Apache 2.0 |
| `github.com/miekg/dns` | DNS queries | BSD |
| `github.com/likexian/whois` | WHOIS lookups | Apache 2.0 |
| `github.com/likexian/whois-parser` | WHOIS parsing | Apache 2.0 |

### 6.2 Development Dependencies

| Tool | Purpose |
|------|---------|
| `golangci-lint` | Code linting |
| `gosec` | Security scanning |
| `go test` | Unit testing |

---

## 7. Success Criteria

The project is considered complete when:

- [x] All phases (1-7) are completed
- [x] All unit tests pass with >80% coverage
- [x] All integration tests pass
- [x] gosec reports no security issues
- [x] golangci-lint reports no errors
- [x] CI/CD pipeline is fully operational
- [x] Release automation creates proper artifacts
- [x] Documentation is complete and accurate
- [x] README includes clear installation and usage instructions

---

## 8. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| crt.sh rate limiting | Limited enumeration | Implement caching and exponential backoff |
| Third-party API changes | Provider breakage | Abstract provider interface, monitor for changes |
| Large domain lists | Memory/time issues | Streaming processing, pagination |
| TLD WHOIS variations | Parsing failures | Handle common formats, fail gracefully |
| API key requirements | Limited functionality | Document required keys, provide fallbacks |
