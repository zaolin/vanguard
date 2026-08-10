.PHONY: all clean build embed install install-systemd

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

clean:
	rm -f vanguard cmd/vanguard/embed/init cmd/vanguard/embed/init-debug

# Install to GOPATH/bin
install: embed
	go install ./cmd/vanguard/

# Install systemd unit for automatic firmware update recovery
install-systemd: install
	install -d $(DESTDIR)/usr/lib/systemd/system
	install -m644 cmd/vanguard/embed/vanguard-pcrlock-relock.service $(DESTDIR)/usr/lib/systemd/system/
	install -d $(DESTDIR)/etc/vanguard
	install -m600 cmd/vanguard/embed/vanguard.env.example $(DESTDIR)/etc/vanguard/vanguard.env.example