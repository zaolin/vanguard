package main

// Version is set at build time via ldflags:
//
//	go build -ldflags "-X main.Version=1.0.0" ./cmd/vanguard/
//
// If not set, defaults to "dev".
var Version = "dev"
