package totp

import (
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

// GenerateQRCodeString returns a compact ASCII-art QR code for the given URI,
// suitable for display in a terminal. Uses ToSmallString (half-block Unicode
// characters) for a QR code that is half the size of the standard ToString
// output, making it easier to scan from smaller terminals.
func GenerateQRCodeString(uri string) (string, error) {
	qr, err := qrcode.New(uri, qrcode.High)
	if err != nil {
		return "", fmt.Errorf("failed to generate QR code: %w", err)
	}

	return qr.ToSmallString(false), nil
}

// GenerateQRCodePNG writes a QR code as a PNG image to the given file path.
func GenerateQRCodePNG(uri string, path string) error {
	return qrcode.WriteFile(uri, qrcode.High, 512, path)
}

// PrintQRCode generates and prints an ASCII QR code for the otpauth URI
// to stdout. Used by `vanguard recovery --enable` for terminal enrollment.
func PrintQRCode(uri string) error {
	qrStr, err := GenerateQRCodeString(uri)
	if err != nil {
		return err
	}
	fmt.Println(qrStr)
	return nil
}
