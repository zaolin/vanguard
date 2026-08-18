.PHONY: all clean build embed install install-systemd ci build-cover

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

all: build

# Build the CLI with embedded init binaries
build: embed
	go build -ldflags "-X main.Version=$(VERSION)" -o vanguard ./cmd/vanguard/

# Build the init binaries for embedding
# Only 2 variants: release (minimal output) and debug (verbose output)
# Both have strict mode always-on (no passphrase fallback without TOTP)
embed: cmd/vanguard/embed/init cmd/vanguard/embed/init-debug

# Release init binary (minimal output, strict mode)
cmd/vanguard/embed/init: $(wildcard init/*.go) $(wildcard init/**/*.go) $(wildcard internal/luks/*.go) $(wildcard internal/tpm/*.go)
	CGO_ENABLED=0 go build -ldflags "-s -w" -o $@ ./init/

# Debug init binary (verbose output, strict mode)
cmd/vanguard/embed/init-debug: $(wildcard init/*.go) $(wildcard init/**/*.go) $(wildcard internal/luks/*.go) $(wildcard internal/tpm/*.go)
	CGO_ENABLED=0 go build -tags debug -ldflags "-s -w" -o $@ ./init/

# CI target: run all fast checks
ci: build
	go test -count=1 ./...
	go vet ./...
	@FILES=$$(gofmt -l $$(find . -name "*.go" -not -path "./graphify-out/*" -not -path "./testdata/*")); \
	if [ -n "$$FILES" ]; then echo "gofmt FAIL:"; echo "$$FILES"; exit 1; \
	else echo "gofmt: OK"; fi

# Build covered init binary + C wrapper for QEMU coverage testing
build-cover: build
	CGO_ENABLED=0 go build -cover -tags debug -o test/init-cover ./init/
	gcc -static -o /tmp/init-cover-wrapper scripts/helpers/init-cover-wrapper.c
	@echo "Cover build complete: test/init-cover + /tmp/init-cover-wrapper"

clean:
	rm -f vanguard cmd/vanguard/embed/init cmd/vanguard/embed/init-debug

# Install to GOPATH/bin
install: embed
	go install ./cmd/vanguard/

# Install systemd unit for automatic firmware update recovery
install-systemd: install
	install -d $(DESTDIR)/usr/lib/systemd/system
	install -m644 cmd/vanguard/embed/vanguard-pcrlock-relock.service $(DESTDIR)/usr/lib/systemd/system/