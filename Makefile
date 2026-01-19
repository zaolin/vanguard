.PHONY: all clean build embed

all: build

# Build the CLI with embedded init binaries
build: embed
	go build -o vanguard ./cmd/vanguard/

# Build the init binaries for embedding
embed: cmd/vanguard/embed/init cmd/vanguard/embed/init-debug

# Release init binary (minimal output)
cmd/vanguard/embed/init: $(wildcard init/*.go) $(wildcard init/**/*.go)
	CGO_ENABLED=0 go build -ldflags "-s -w" -o $@ ./init/

# Debug init binary (verbose output)
cmd/vanguard/embed/init-debug: $(wildcard init/*.go) $(wildcard init/**/*.go)
	CGO_ENABLED=0 go build -tags debug -ldflags "-s -w" -o $@ ./init/

clean:
	rm -f vanguard cmd/vanguard/embed/init cmd/vanguard/embed/init-debug

# Install to GOPATH/bin
install: embed
	go install ./cmd/vanguard/
