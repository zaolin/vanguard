package main

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"
)

// EFI variable GUIDs for Secure Boot databases.
const (
	efiVarGUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
	dbGUID     = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
	efiVarBase = "/sys/firmware/efi/efivars/"
)

// EFI_SIGNATURE_LIST type GUIDs.
var (
	efiCertX509GUID       = []byte{0xa5, 0xc0, 0x59, 0xa1, 0xe4, 0x94, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72, 0x14}
	efiCertX509SHA256GUID = []byte{0xe3, 0xb7, 0x8d, 0x44, 0x97, 0x87, 0x46, 0x43, 0xa5, 0x4d, 0xf5, 0x6d, 0xe0, 0x60, 0xb7, 0x0c}
	efiCertSHA256GUID     = []byte{0xc5, 0xc9, 0x5e, 0x26, 0x97, 0x87, 0x46, 0x43, 0xa5, 0x4d, 0xf5, 0x6d, 0xe0, 0x60, 0xb7, 0x0c}
	efiCertRSA2048GUID    = []byte{0x87, 0x91, 0x1b, 0xe1, 0xe5, 0x8c, 0x4e, 0x4b, 0xa5, 0x1b, 0x1e, 0x6b, 0x0b, 0xcb, 0x8c, 0x14}
)

// secureBootInfo contains parsed Secure Boot key database information.
type secureBootInfo struct {
	Enabled    bool       `json:"enabled"`
	SetupMode  bool       `json:"setupMode"`
	PK         []certInfo `json:"pk"`
	KEK        []certInfo `json:"kek"`
	DB         []certInfo `json:"db"`
	DBX        []certInfo `json:"dbx"`
	DBT        []certInfo `json:"dbt,omitempty"`
	CustomKeys bool       `json:"customKeys"`
	Warnings   []string   `json:"warnings,omitempty"`
}

// certInfo represents a single certificate from an EFI signature database.
type certInfo struct {
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	NotBefore  string `json:"notBefore,omitempty"`
	NotAfter   string `json:"notAfter,omitempty"`
	Expired    bool   `json:"expired,omitempty"`
	IsX509Cert bool   `json:"isX509Cert"`
	HashType   string `json:"hashType,omitempty"`
}

// collectSecureBootStatus reads EFI variables and parses Secure Boot key databases.
func collectSecureBootStatus() *secureBootInfo {
	info := &secureBootInfo{}

	// Read SecureBoot and SetupMode
	info.Enabled = readEFIBool(efiVarBase + "SecureBoot-" + efiVarGUID)
	info.SetupMode = readEFIBool(efiVarBase + "SetupMode-" + efiVarGUID)

	// Parse key databases
	info.PK = parseEFISignatureDB(efiVarBase + "PK-" + efiVarGUID)
	info.KEK = parseEFISignatureDB(efiVarBase + "KEK-" + efiVarGUID)
	info.DB = parseEFISignatureDB(efiVarBase + "db-" + dbGUID)

	// dbx might be under the standard GUID or the db GUID
	dbx := parseEFISignatureDB(efiVarBase + "dbx-" + efiVarGUID)
	if len(dbx) == 0 {
		dbx = parseEFISignatureDB(efiVarBase + "dbx-" + dbGUID)
	}
	info.DBX = dbx

	// dbt (timestamp database) — rare
	info.DBT = parseEFISignatureDB(efiVarBase + "dbt-" + efiVarGUID)
	if len(info.DBT) == 0 {
		info.DBT = parseEFISignatureDB(efiVarBase + "dbt-" + dbGUID)
	}

	// Determine if keys are custom (non-factory)
	// Factory default = PK/KEK/db contain Microsoft or standard OEM certificates
	// Custom = PK/KEK/db contain user-generated certificates
	info.CustomKeys = isCustomKeys(info.PK, info.KEK, info.DB)

	// Security warnings
	info.Warnings = checkSecureBootWarnings(info)

	return info
}

// readEFIBool reads a boolean EFI variable (4-byte attributes + 1-byte value).
func readEFIBool(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if len(data) >= 5 {
		return data[4] == 1
	}
	return false
}

// parseEFISignatureDB reads an EFI variable and parses EFI_SIGNATURE_LIST entries.
// Returns a list of certificate info for each X.509 certificate found.
// For non-X.509 entries (hash-based), returns a certInfo with the hash type.
func parseEFISignatureDB(path string) []certInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// Skip 4-byte EFI attributes
	varData := data[4:]
	if len(varData) < 28 {
		return nil
	}

	var certs []certInfo

	offset := 0
	for offset+28 <= len(varData) {
		sigType := varData[offset : offset+16]
		listSize := int(binary.LittleEndian.Uint32(varData[offset+16 : offset+20]))
		headerSize := int(binary.LittleEndian.Uint32(varData[offset+20 : offset+24]))
		sigSize := int(binary.LittleEndian.Uint32(varData[offset+24 : offset+28]))

		if listSize == 0 || sigSize == 0 || offset+listSize > len(varData) {
			break
		}

		// Parse each signature in this list
		sigOffset := offset + 28 + headerSize
		sigEnd := offset + listSize

		for sigOffset+sigSize <= sigEnd && sigSize > 0 {
			sigData := varData[sigOffset : sigOffset+sigSize]

			if isX509SigType(sigType) && len(sigData) > 16 {
				// X.509 cert: 16-byte owner GUID + DER certificate
				certDER := sigData[16:]
				cert, err := x509.ParseCertificate(certDER)
				if err == nil {
					ci := certInfo{
						Subject:    cert.Subject.String(),
						Issuer:     cert.Issuer.String(),
						NotBefore:  cert.NotBefore.Format("2006-01-02"),
						NotAfter:   cert.NotAfter.Format("2006-01-02"),
						IsX509Cert: true,
					}
					if time.Now().After(cert.NotAfter) {
						ci.Expired = true
					}
					certs = append(certs, ci)
				} else {
					certs = append(certs, certInfo{
						IsX509Cert: true,
						Subject:    fmt.Sprintf("(parse error, %d bytes)", len(certDER)),
					})
				}
			} else {
				// Hash-based or other signature type
				hashType := "unknown"
				if bytesEqual(sigType, efiCertSHA256GUID) {
					hashType = "SHA256"
				} else if bytesEqual(sigType, efiCertX509SHA256GUID) {
					hashType = "X509+SHA256"
				} else if bytesEqual(sigType, efiCertRSA2048GUID) {
					hashType = "RSA2048"
				}
				certs = append(certs, certInfo{
					HashType:   hashType,
					IsX509Cert: false,
					Subject:    fmt.Sprintf("%s hash (%d bytes)", hashType, len(sigData)),
				})
			}

			sigOffset += sigSize
		}

		offset += listSize
	}

	return certs
}

// isX509SigType checks if the signature type GUID is EFI_CERT_X509.
func isX509SigType(sigType []byte) bool {
	return bytesEqual(sigType, efiCertX509GUID)
}

// bytesEqual compares two byte slices.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// isCustomKeys checks whether the PK/KEK/db certificates are user-generated
// (custom) rather than factory defaults (Microsoft, OEM, etc.).
//
// Heuristic: if any PK certificate subject does NOT contain well-known
// factory issuer strings ("Microsoft", "OEM", "AMI", "Insyde", "EDK2"),
// it is considered custom. The more non-custom certificates exist across
// PK/KEK/db, the worse for the threat model — each is a potential trust
// anchor an attacker could exploit.
func isCustomKeys(pk, kek, db []certInfo) bool {
	// If PK is empty, keys are not custom (they're absent)
	if len(pk) == 0 {
		return false
	}

	// Check if ALL PK certs are non-factory
	allCustom := true
	for _, c := range pk {
		if isFactorySubject(c.Subject) {
			allCustom = false
			break
		}
	}
	return allCustom
}

// isFactorySubject checks if a certificate subject looks like a factory
// default key (Microsoft, OEM, AMI, Insyde, EDK2, etc.).
func isFactorySubject(subject string) bool {
	factoryMarkers := []string{
		"microsoft", "Microsoft",
		"OEM", "AMI", "Insyde", "EDK2",
		"Intel", "AMD", "Lenovo", "Dell", "HP",
		"Acer", "ASUS", "ASRock", "Gigabyte",
		"MSI", "Toshiba", "Fujitsu", "Samsung",
	}
	for _, marker := range factoryMarkers {
		if strings.Contains(subject, marker) {
			return true
		}
	}
	return false
}

// countNonCustomCerts counts certificates across PK/KEK/db that are NOT
// custom (i.e., factory/OEM certificates). More non-custom certs = worse
// for the threat model, as each represents an additional trust anchor.
func countNonCustomCerts(info *secureBootInfo) int {
	count := 0
	for _, c := range info.PK {
		if isFactorySubject(c.Subject) {
			count++
		}
	}
	for _, c := range info.KEK {
		if isFactorySubject(c.Subject) {
			count++
		}
	}
	for _, c := range info.DB {
		if isFactorySubject(c.Subject) {
			count++
		}
	}
	return count
}

// checkSecureBootWarnings generates security warnings from the parsed Secure Boot info.
func checkSecureBootWarnings(info *secureBootInfo) []string {
	var warnings []string

	// Critical: Setup Mode (no PK)
	if info.SetupMode {
		warnings = append(warnings, "CRITICAL: System is in Setup Mode — no Platform Key enrolled, Secure Boot is not enforcing")
	}

	// Critical: Secure Boot disabled
	if !info.Enabled && !info.SetupMode {
		warnings = append(warnings, "CRITICAL: Secure Boot is disabled — initrd can be replaced (evil maid attack)")
	}

	// Warning: PK empty
	if len(info.PK) == 0 && !info.SetupMode {
		warnings = append(warnings, "WARNING: Platform Key (PK) is empty — Secure Boot cannot enforce")
	}

	// Warning: dbx not configured
	if len(info.DBX) == 0 {
		warnings = append(warnings, "WARNING: No dbx (revocation list) — known-vulnerable bootloaders are not blocked")
	}

	// Warning: expired certificates
	for _, c := range info.PK {
		if c.Expired {
			warnings = append(warnings, fmt.Sprintf("WARNING: PK certificate expired (notAfter: %s) — new signatures may be rejected", c.NotAfter))
		}
	}
	for _, c := range info.KEK {
		if c.Expired {
			warnings = append(warnings, fmt.Sprintf("WARNING: KEK certificate expired (notAfter: %s) — db/dbx updates may fail", c.NotAfter))
		}
	}
	for _, c := range info.DB {
		if c.Expired {
			warnings = append(warnings, fmt.Sprintf("WARNING: db certificate expired (notAfter: %s) — signed binaries may be rejected", c.NotAfter))
		}
	}

	// Info: non-custom (factory) certificates in the trust chain
	nonCustomCount := countNonCustomCerts(info)
	if nonCustomCount > 0 && info.CustomKeys {
		warnings = append(warnings, fmt.Sprintf("INFO: %d factory/OEM certificate(s) in PK/KEK/db alongside custom keys", nonCustomCount))
	} else if nonCustomCount > 0 && !info.CustomKeys {
		warnings = append(warnings, fmt.Sprintf("INFO: Using factory default keys (%d certificate(s) in PK/KEK/db) — consider enrolling custom keys for stronger security", nonCustomCount))
	}

	return warnings
}

// truncateSubject truncates a certificate subject string for display.
func truncateSubject(s string) string {
	if len(s) > 50 {
		return s[:47] + "..."
	}
	return s
}

// pluralY returns "y" or "ies" for pluralization.
func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
