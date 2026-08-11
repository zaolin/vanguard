package totp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateQRCodePNG(t *testing.T) {
	dir := t.TempDir()
	pngPath := filepath.Join(dir, "qr.png")
	uri := "otpauth://totp/Test:test?secret=JBSWY3DPEHPK3PXP&issuer=Test"

	if err := GenerateQRCodePNG(uri, pngPath); err != nil {
		t.Fatalf("GenerateQRCodePNG: %v", err)
	}

	info, err := os.Stat(pngPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() == 0 {
		t.Error("PNG file is empty")
	}
}

func TestPrintQRCode(t *testing.T) {
	uri := "otpauth://totp/Test:test?secret=JBSWY3DPEHPK3PXP&issuer=Test"
	if err := PrintQRCode(uri); err != nil {
		t.Fatalf("PrintQRCode: %v", err)
	}
}