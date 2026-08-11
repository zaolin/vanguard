package recovery

import "testing"

func TestAbs(t *testing.T) {
	tests := []struct {
		input int64
		want  int64
	}{
		{0, 0},
		{5, 5},
		{-5, 5},
		{100, 100},
		{-100, 100},
		{1, 1},
		{-1, 1},
	}
	for _, tt := range tests {
		if got := abs(tt.input); got != tt.want {
			t.Errorf("abs(%d) = %d, want %d", tt.input, got, tt.want)
		}
	}
}