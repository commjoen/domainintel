# domainintel Makefile

# Build variables
BINARY_NAME=domainintel
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Directories
CMD_DIR=./cmd/domainintel
DIST_DIR=./dist

.PHONY: all build clean test test-coverage lint lint-install security deps tidy update help

# Default target
all: deps lint test build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) $(CMD_DIR)
	@echo "Build complete: $(BINARY_NAME)"

# Build for all platforms
build-all: clean
	@echo "Building for all platforms..."
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)
	GOOS=windows GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-arm64.exe $(CMD_DIR)
	@echo "Build complete for all platforms"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -rf $(DIST_DIR)

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Install linting tools
lint-install:
	@echo "Installing golangci-lint..."
	@which golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
lint: lint-install
	@echo "Running linter..."
	golangci-lint run ./...

# Install security scanning tools
security-install:
	@echo "Installing gosec..."
	@which gosec > /dev/null || go install github.com/securego/gosec/v2/cmd/gosec@latest

# Run security scan
security: security-install
	@echo "Running security scan..."
	gosec ./...

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download

# Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy

# Update Go version and dependencies
update:
	@echo "Updating Go version and dependencies..."
	@echo "Checking latest Go version..."
	@LATEST_GO=$$(curl -s https://go.dev/VERSION?m=text | head -n1 | sed 's/go//'); \
	if [ -z "$$LATEST_GO" ]; then \
	echo "Error: Failed to fetch latest Go version"; \
	exit 1; \
	fi; \
	echo "Latest Go version: $$LATEST_GO"; \
	echo "Current go.mod version: $$(grep '^go ' go.mod | awk '{print $$2}')"; \
	echo "Updating go.mod to Go $$LATEST_GO..."; \
	go mod edit -go=$$LATEST_GO; \
	echo "Updating GitHub Actions workflows..."; \
	find .github/workflows -name '*.yml' -o -name '*.yaml' | while read -r file; do \
	if grep -q 'go-version:' "$$file"; then \
	sed -i.bak "s/go-version: *['\"]?[0-9.]*['\"]*/go-version: '$$LATEST_GO'/" "$$file" && rm -f "$$file.bak"; \
	echo "  Updated $$file"; \
	fi; \
	done; \
	echo "Updating dependencies..."; \
	$(GOMOD) tidy; \
	$(GOGET) -u ./...; \
	$(GOMOD) tidy; \
	echo "Update complete!"; \
	echo "Summary:"; \
	echo "  Go version: $$LATEST_GO"; \
	echo "  Updated files:"; \
	echo "    - go.mod"; \
	echo "    - go.sum"; \
	git diff --name-only 2>/dev/null | grep -E '(go.mod|go.sum|\.github/)' | sed 's/^/    - /' || echo "    (no files changed)"; \
	echo ""; \
	echo "Next steps:"; \
	echo "  1. Review changes: git diff"; \
	echo "  2. Test the build: make test"; \
	echo "  3. Commit changes: git add go.mod go.sum .github/ && git commit -m 'chore: update Go to $$LATEST_GO and dependencies'"

# Run the application
run: build
	./$(BINARY_NAME) --domains example.com

# Show help
help:
	@echo "Available targets:"
	@echo "  all           - Run deps, lint, test, and build (default)"
	@echo "  build         - Build the binary"
	@echo "  build-all     - Build for all platforms (Linux, macOS, Windows)"
	@echo "  clean         - Remove build artifacts"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  lint          - Run linter (installs golangci-lint if needed)"
	@echo "  security      - Run security scan (installs gosec if needed)"
	@echo "  deps          - Download dependencies"
	@echo "  tidy          - Tidy go.mod and go.sum"
	@echo "  update        - Update Go version and dependencies to latest"
	@echo "  run           - Build and run with example domain"
	@echo "  help          - Show this help message"
