VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOBUILD := go build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: build build-windows test lint vuln spec clean

build:
	$(GOBUILD) -o bin/fleet-mcp ./cmd/fleet-mcp

build-windows:
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o bin/fleet-mcp.exe ./cmd/fleet-mcp

test:
	go test -race ./...

# staticcheck 0.8.1 cannot read go1.27.x export data yet; see ci.yml.
lint:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	go vet ./...
	GOTOOLCHAIN=go1.27.1 go run honnef.co/go/tools/cmd/staticcheck@latest ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Download the REST spec and GraphQL schema from the Fleet Manager named by
# FLEET_MCP_URL into ./spec (git-ignored). Needs "expose-swagger": true.
spec:
	go run ./cmd/fleet-mcp spec -out spec

clean:
	rm -rf bin dist
