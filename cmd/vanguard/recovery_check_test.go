package main

import (
	"testing"
)

// TestAbs64 verifies the abs64 helper function used by runCheck.
func TestAbs64(t *testing.T) {
	tests := []struct {
		input    int64
		expected int64
	}{
		{0, 0},
		{100, 100},
		{-100, 100},
		{1, 1},
		{-1, 1},
		{300, 300},
		{-300, 300},
	}

	for _, tt := range tests {
		got := abs64(tt.input)
		if got != tt.expected {
			t.Errorf("abs64(%d) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}
