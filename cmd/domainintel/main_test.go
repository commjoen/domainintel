// Package main provides tests for the domainintel CLI
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func TestParseDomains(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"single domain", "example.com", []string{"example.com"}},
		{"multiple domains", "example.com,example.org", []string{"example.com", "example.org"}},
		{"with spaces", "example.com, example.org", []string{"example.com", "example.org"}},
		{"with wildcard", "*.example.com", []string{"example.com"}},
		{"mixed wildcards", "*.example.com,example.org", []string{"example.com", "example.org"}},
		{"empty string", "", []string{}},
		{"only commas", ",,,", []string{}},
		{"uppercase", "EXAMPLE.COM", []string{"example.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDomains(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("parseDomains(%q) = %v, want %v", tt.input, result, tt.expected)
				return
			}
			for i, domain := range result {
				if domain != tt.expected[i] {
					t.Errorf("parseDomains(%q)[%d] = %q, want %q", tt.input, i, domain, tt.expected[i])
				}
			}
		})
	}
}

func TestRootCmdFlags(t *testing.T) {
	// Test that all flags are properly registered
	flags := []struct {
		name     string
		short    string
		hasValue bool
	}{
		{"domains", "d", true},
		{"format", "f", true},
		{"out", "o", true},
		{"timeout", "t", true},
		{"concurrent", "c", true},
		{"verbose", "v", false},
		{"progress", "p", false},
		{"dig", "", false},
		{"whois", "", false},
		{"providers", "", true},
	}

	for _, flag := range flags {
		t.Run(flag.name, func(t *testing.T) {
			f := rootCmd.Flags().Lookup(flag.name)
			if f == nil {
				t.Errorf("Flag --%s should exist", flag.name)
				return
			}
			if f.Shorthand != flag.short {
				t.Errorf("Flag --%s should have short form -%s, got -%s", flag.name, flag.short, f.Shorthand)
			}
		})
	}
}

func TestRootCmdUsage(t *testing.T) {
	// Capture the output
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)

	// Test usage output
	rootCmd.SetArgs([]string{"--help"})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("Help command failed: %v", err)
	}

	output := buf.String()
	expectedContents := []string{
		"domainintel",
		"reconnaissance",
		"--domains",
		"--format",
	}

	for _, expected := range expectedContents {
		if !strings.Contains(output, expected) {
			t.Errorf("Help output should contain %q", expected)
		}
	}
}

func TestRootCmdVersion(t *testing.T) {
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)

	rootCmd.SetArgs([]string{"--version"})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("Version command failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "domainintel") {
		t.Error("Version output should contain 'domainintel'")
	}
}

func TestInitVersionPreservesLDFLAGS(t *testing.T) {
	// Save original version
	originalVersion := version
	defer func() { version = originalVersion }()

	// When version is set via LDFLAGS (not "dev"), initVersion should not change it
	version = "v1.2.3"
	initVersion()

	if version != "v1.2.3" {
		t.Errorf("initVersion should preserve LDFLAGS version, got %q, want %q", version, "v1.2.3")
	}
}

func TestInitVersionFromBuildInfo(t *testing.T) {
	// Save original version
	originalVersion := version
	defer func() { version = originalVersion }()

	// When version is "dev", initVersion should try to get version from build info
	version = "dev"
	initVersion()

	// After initVersion, version should either remain "dev" (if build info not available)
	// or be set to the build info version
	// We can't guarantee which it will be in tests, but we can verify it doesn't panic
	// and the version is non-empty
	if version == "" {
		t.Error("initVersion should not set version to empty string")
	}
}

func TestPrintProgress(t *testing.T) {
	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Call printProgress
	printProgress("example.com", 5, 10)

	// Restore stderr
	w.Close()
	os.Stderr = oldStderr

	// Read output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output contains progress information
	if !strings.Contains(output, "example.com") {
		t.Error("Progress output should contain domain name")
	}
	if !strings.Contains(output, "50%") {
		t.Error("Progress output should show 50% for 5/10")
	}
}

func TestPrintProgressComplete(t *testing.T) {
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	printProgress("test.com", 10, 10)

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "100%") {
		t.Error("Progress output should show 100% when complete")
	}
}

func TestPrintProgressInitial(t *testing.T) {
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Test initial progress (0%) which should be shown before any subdomain checks
	printProgress("example.com", 0, 10)

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "example.com") {
		t.Error("Progress output should contain domain name")
	}
	if !strings.Contains(output, "0%") {
		t.Error("Progress output should show 0% for initial progress")
	}
	if !strings.Contains(output, "0/10") {
		t.Error("Progress output should show 0/10 for initial progress")
	}
}

func TestRunWithInvalidDomain(t *testing.T) {
	// Set the domains flag to an invalid value
	domains = "invalid domain with spaces"

	// Create test context
	err := run(rootCmd, []string{})

	// Reset
	domains = ""

	if err == nil {
		t.Error("Expected error for invalid domain")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("Error should mention 'invalid', got: %v", err)
	}
}

func TestRunWithEmptyDomains(t *testing.T) {
	domains = ""

	err := run(rootCmd, []string{})

	if err == nil {
		t.Error("Expected error for empty domains")
	}
	if !strings.Contains(err.Error(), "no valid domains") {
		t.Errorf("Error should mention 'no valid domains', got: %v", err)
	}
}

func TestRunWithInvalidFormat(t *testing.T) {
	domains = "example.com"
	format = "invalid"

	err := run(rootCmd, []string{})

	// Reset
	domains = ""
	format = "text"

	if err == nil {
		t.Error("Expected error for invalid format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("Error should mention 'unsupported format', got: %v", err)
	}
}

func TestRunWithTooManyDomains(t *testing.T) {
	// Create a string with 101 domains
	domainSlice := make([]string, 101)
	for i := 0; i < 101; i++ {
		domainSlice[i] = fmt.Sprintf("domain%d.com", i)
	}
	domains = strings.Join(domainSlice, ",")

	err := run(rootCmd, []string{})

	// Reset
	domains = ""

	if err == nil {
		t.Error("Expected error for too many domains")
	}
	if !strings.Contains(err.Error(), "too many domains") {
		t.Errorf("Error should mention 'too many domains', got: %v", err)
	}
}

func TestValidateOutputPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty path", "", false},
		{"simple filename", "results.json", false},
		{"relative path", "./output/results.json", false},
		{"parent directory", "../results.json", false},
		{"absolute path home", "/home/user/results.json", false},
		{"sensitive etc", "/etc/passwd", true},
		{"sensitive var", "/var/log/test.log", true},
		{"sensitive usr", "/usr/bin/test", true},
		{"sensitive root", "/root/test", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOutputPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOutputPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}
