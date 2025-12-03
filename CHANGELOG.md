# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2025-12-03

### Added
- **Automatic Version Update Checking**
  - `--version` flag now checks GitHub for latest release
  - Shows update notification when newer version is available
  - Displays download link and update instructions
  - 3-second timeout to avoid hanging
  - Non-blocking with graceful fallback on network errors
  - GitHub API integration for release checking

## [0.1.1] - 2025-12-03

### Added

- **Certificate Transparency (CT) Log Integration**
  - Query crt.sh for subdomain enumeration
  - Automatic subdomain discovery from CT logs
  - Domain validation to prevent invalid queries

- **Reachability Checking**
  - HTTP/HTTPS availability testing for discovered subdomains
  - TLS certificate validation and expiration checking
  - Concurrent subdomain checking with configurable worker pools
  - Support for both IPv4 and IPv6 resolution

- **Extended DNS Queries (`--dig` flag)**
  - A (IPv4) and AAAA (IPv6) record lookups
  - MX (Mail Exchange) records with priority
  - TXT (Text) records for SPF, DKIM, and domain verification
  - NS (Name Server) records
  - CNAME (Canonical Name) records
  - SOA (Start of Authority) records with serial, refresh, retry, and expire data

- **WHOIS Integration (`--whois` flag)**
  - Domain registration information lookup
  - Registrar details
  - Registration and expiration dates
  - Registrant contact information
  - Name server information
  - Automatic base domain extraction from subdomains
  - Rate limiting and caching support

- **Third-Party Security Providers (`--providers` flag)**
  - VirusTotal integration for domain reputation
    - Malicious/suspicious URL detection
    - Community voting scores
    - Category classifications
  - URLVoid integration for multi-engine scanning
    - Aggregated reputation from multiple security engines
    - Detection count and engine details
  - Provider validation with required API key checks
  - Clear error messages for missing or invalid API keys

- **Multiple Output Formats**
  - Text output with human-readable formatting
  - JSON output for programmatic consumption
  - CSV output for spreadsheet analysis
  - File output support with security validation

- **CLI Features**
  - Multi-domain scanning with comma-separated input
  - Verbose logging mode (`-v` flag)
  - Progress bar for long-running scans (`-p` flag)
  - Configurable HTTP timeout and concurrency limits
  - Graceful shutdown on interrupt (Ctrl+C)
  - Domain count limiting (max 100) to prevent abuse

- **Security Features**
  - Output path validation to prevent directory traversal
  - Domain validation before processing
  - Rate limiting for external API calls
  - Secure default timeouts and connection handling

### Fixed
- **WHOIS Flag**: Now correctly executes by ensuring base domain is always included in results
- **Providers Flag**: Validates requested providers and API keys, fails fast with clear errors instead of silently ignoring
- Code formatting compliance with `gofmt`
- Preallocation of slices where appropriate for linter compliance

### Changed
- Improved help text and examples for all CLI flags
- Enhanced provider flag description with API key requirements
- Better error messages throughout the application
- Consistent code formatting and linting
- Version output now includes update check and status indicator

### Technical Details
- Built with Go 1.21+
- Uses Cobra for CLI framework
- Implements context-based cancellation
- Concurrent processing with worker pools and semaphores
- Structured logging with verbosity levels
- Comprehensive test coverage (target: >80%)

## [0.1.0] - Initial Development

### Added
- Basic project structure
- Core domain intelligence gathering framework
- Initial CI/CD pipeline setup

---

## How to Use

### Basic Usage
```bash
# Simple subdomain enumeration
domainintel --domains example.com

# Check version and updates
domainintel --version

# Full reconnaissance with DNS and WHOIS
domainintel --domains example.com --dig --whois

# Multiple domains with JSON output
domainintel --domains example.com,example.org --format json --out results.json
```

### Third-Party Providers
```bash
# Set up API keys
export VT_API_KEY=your_virustotal_key
export URLVOID_API_KEY=your_urlvoid_key

# Run with providers
domainintel --domains example.com --providers vt,urlvoid
```

### Advanced Options
```bash
# Enable all features with progress bar and verbose logging
domainintel --domains example.com \
  --dig \
  --whois \
  --providers vt,urlvoid \
  --format json \
  --out scan-results.json \
  --concurrent 20 \
  --timeout 15s \
  --progress \
  --verbose
```

---

## Environment Variables

| Variable | Description | Required For |
|----------|-------------|--------------|
| `VT_API_KEY` | VirusTotal API key | `--providers vt` |
| `URLVOID_API_KEY` | URLVoid API key | `--providers urlvoid` |

---

## Upcoming Features

- [ ] Additional DNS record types (PTR, SRV, CAA)
- [ ] More third-party providers (Shodan, AlienVault OTX)
- [ ] Historical subdomain tracking
- [ ] Screenshot capture for live domains
- [ ] Port scanning integration
- [ ] Custom DNS resolver support
- [ ] Rate limiting configuration
- [ ] Retry logic for failed requests
- [ ] Cache management commands
- [ ] Export to additional formats (HTML, Markdown)
- [ ] Semantic version comparison for update checks

[Unreleased]: https://github.com/commjoen/domainintel/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/commjoen/domainintel/releases/tag/v0.1.1
[0.1.0]: https://github.com/commjoen/domainintel/releases/tag/v0.1.0