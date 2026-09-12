package main

import (
	"testing"

	"github.com/alecthomas/kong"
)

// TestCLIGrammar is a smoke test for kong grammar construction: any CLI
// struct invalid for kong (e.g. an enum field without required or default,
// kong v0.8) panics eagerly in kong.Parse — for EVERY subcommand, not just
// the one with the bad field. go build/go test of other packages never
// parse the CLI, so this regression is only caught here.
//
// kong.New builds the full grammar without executing hooks (version/help
// flags call os.Exit during Parse, so full-parses can't run in-process).
func TestCLIGrammar(t *testing.T) {
	k, err := kong.New(&CLI{},
		kong.Name("vanguard"),
		kong.Vars{"version": Version},
	)
	if err != nil {
		t.Fatalf("kong grammar construction failed: %v", err)
	}
	_ = k
}

// TestGenerateCompressionValidation covers the compression validation that
// replaced the kong enum tag.
func TestGenerateCompressionValidation(t *testing.T) {
	valid := map[string]bool{"zstd": true, "gzip": true, "none": true, "": true}
	for v, want := range valid {
		if got := isValidCompression(v); got != want {
			t.Errorf("isValidCompression(%q) = %v, want %v", v, got, want)
		}
	}
	if isValidCompression("brotli") {
		t.Error("brotli should be invalid")
	}
}
