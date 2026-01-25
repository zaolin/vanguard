.PHONY: all clean build embed

all: build

# Build the CLI with embedded init binaries
build: embed
	go build -o vanguard ./cmd/vanguard/

# Build the init binaries for embedding
embed: cmd/vanguard/embed/init cmd/vanguard/embed/init-debug cmd/vanguard/embed/init-strict cmd/vanguard/embed/init-debug-strict

# Release init binary (minimal output)
cmd/vanguard/embed/init: $(wildcard init/*.go) $(wildcard init/**/*.go)
	CGO_ENABLED=0 go build -ldflags "-s -w" -o $@ ./init/

# Debug init binary (verbose output)
cmd/vanguard/embed/init-debug: $(wildcard init/*.go) $(wildcard init/**/*.go)
	CGO_ENABLED=0 go build -tags debug -ldflags "-s -w" -o $@ ./init/

# Strict mode init binary (token-only, no passphrase fallback)
cmd/vanguard/embed/init-strict: $(wildcard init/*.go) $(wildcard init/**/*.go)
	CGO_ENABLED=0 go build -tags strict -ldflags "-s -w" -o $@ ./init/

# Debug + strict mode init binary
cmd/vanguard/embed/init-debug-strict: $(wildcard init/*.go) $(wildcard init/**/*.go)
	CGO_ENABLED=0 go build -tags "debug,strict" -ldflags "-s -w" -o $@ ./init/

clean:
	rm -f vanguard cmd/vanguard/embed/init cmd/vanguard/embed/init-debug cmd/vanguard/embed/init-strict cmd/vanguard/embed/init-debug-strict

# Install to GOPATH/bin
install: embed
	go install ./cmd/vanguard/
