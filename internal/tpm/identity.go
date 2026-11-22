package tpm

import (
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
)

// TPMFamily classifies a TPM by its vendor for advisory purposes.
type TPMFamily string

const (
	TPMFamilyInfineon  TPMFamily = "infineon"
	TPMFamilyIntel     TPMFamily = "intel"
	TPMFamilyAMD       TPMFamily = "amd"
	TPMFamilyST        TPMFamily = "st"
	TPMFamilyNuvoton   TPMFamily = "nuvoton"
	TPMFamilySimulator TPMFamily = "simulator"
	TPMFamilyUnknown   TPMFamily = "unknown"
)

// TPMIdentity describes the TPM's vendor and firmware as the TPM itself
// reports them (TPM2_GetCapability, TPM_PT_*).
type TPMIdentity struct {
	// ManufacturerName is the decoded 4-byte manufacturer code
	// (TPM_PT_MANUFACTURER), e.g. "INTC", "IFX ", "AMD ".
	ManufacturerName string
	// Manufacturer is the raw manufacturer value.
	Manufacturer uint32
	// VendorString is TPM_PT_VENDOR_STRING_1..4 concatenated and trimmed.
	VendorString string
	// VendorTPMType is TPM_PT_VENDOR_TPM_TYPE.
	VendorTPMType uint32
	// FirmwareVersion1 and FirmwareVersion2 are TPM_PT_FIRMWARE_VERSION_1/2.
	FirmwareVersion1 uint32
	FirmwareVersion2 uint32
}

// Family classifies the TPM by manufacturer code and vendor string.
//
// The simulator is detected by its vendor string, not by the "IBM " vendor
// code alone: real IBM TPMs exist, and calling one a simulator would be a
// false claim.
func (i TPMIdentity) Family() TPMFamily {
	// swtpm reports vendor "SW   TPM" and manufacturer "IBM\x00": compare a
	// normalized form without spaces and NUL padding.
	vendor := strings.ToLower(strings.NewReplacer(" ", "", "\x00", "").Replace(i.VendorString))
	if strings.Contains(vendor, "swtpm") || strings.Contains(vendor, "simulator") {
		return TPMFamilySimulator
	}

	switch strings.TrimRight(i.ManufacturerName, "\x00 ") {
	case "IFX":
		return TPMFamilyInfineon
	case "INTC":
		return TPMFamilyIntel
	case "AMD":
		return TPMFamilyAMD
	case "STM":
		return TPMFamilyST
	case "NTC":
		return TPMFamilyNuvoton
	default:
		return TPMFamilyUnknown
	}
}

// IsFirmwareTPM reports whether the TPM is implemented in firmware on the
// host CPU (Intel PTT, AMD fTPM), i.e. whether there is no discrete TPM bus
// an attacker could tap.
func (i TPMIdentity) IsFirmwareTPM() bool {
	switch i.Family() {
	case TPMFamilyIntel, TPMFamilyAMD:
		return true
	default:
		return false
	}
}

// FirmwareVersionString renders the firmware version as reported by the TPM.
func (i TPMIdentity) FirmwareVersionString() string {
	if i.FirmwareVersion2 != 0 {
		return fmt.Sprintf("%d.%d", i.FirmwareVersion1, i.FirmwareVersion2)
	}
	return fmt.Sprintf("%d", i.FirmwareVersion1)
}

// ReadIdentity reads the TPM's vendor and firmware properties.
func (c *Client) ReadIdentity() (*TPMIdentity, error) {
	tpm, err := c.openTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTManufacturer),
		PropertyCount: 8,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("GetCapability(TPM properties): %w", err)
	}

	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return nil, fmt.Errorf("decode TPM properties: %w", err)
	}

	id := &TPMIdentity{}
	for _, p := range props.TPMProperty {
		switch p.Property {
		case tpm2.TPMPTManufacturer:
			id.Manufacturer = p.Value
			id.ManufacturerName = strings.TrimRight(string([]byte{
				byte(p.Value >> 24), byte(p.Value >> 16), byte(p.Value >> 8), byte(p.Value),
			}), "\x00 ")
		case tpm2.TPMPTVendorString1:
			id.VendorString += u32ToString(p.Value)
		case tpm2.TPMPTVendorString2:
			id.VendorString += u32ToString(p.Value)
		case tpm2.TPMPTVendorString3:
			id.VendorString += u32ToString(p.Value)
		case tpm2.TPMPTVendorString4:
			id.VendorString += u32ToString(p.Value)
		case tpm2.TPMPTVendorTPMType:
			id.VendorTPMType = p.Value
		case tpm2.TPMPTFirmwareVersion1:
			id.FirmwareVersion1 = p.Value
		case tpm2.TPMPTFirmwareVersion2:
			id.FirmwareVersion2 = p.Value
		}
	}
	id.VendorString = strings.TrimRight(id.VendorString, "\x00 ")

	return id, nil
}

// PermanentFlags holds TPMA_PERMANENT bits (TPM 2.0 spec, Part 2).
type PermanentFlags uint32

const (
	// PermanentOwnerAuthSet means an owner hierarchy auth value is configured.
	PermanentOwnerAuthSet PermanentFlags = 0x00000001
	// PermanentLockoutAuthSet means a lockout auth value is configured.
	PermanentLockoutAuthSet PermanentFlags = 0x00000004
	// PermanentInLockout means the TPM is in dictionary-attack lockout.
	PermanentInLockout PermanentFlags = 0x00000010
)

// ReadPermanentFlags reads TPM_PT_PERMANENT.
//
// This is the read-only way to learn whether an owner/lockout auth is
// configured: probing it with an empty authorization would risk consuming a
// dictionary-attack attempt.
func (c *Client) ReadPermanentFlags() (PermanentFlags, error) {
	tpm, err := c.openTPM()
	if err != nil {
		return 0, err
	}
	defer tpm.Close()

	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTPermanent),
		PropertyCount: 1,
	}.Execute(tpm)
	if err != nil {
		return 0, fmt.Errorf("GetCapability(TPM_PT_PERMANENT): %w", err)
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, fmt.Errorf("decode TPM_PT_PERMANENT: %w", err)
	}
	for _, p := range props.TPMProperty {
		if p.Property == tpm2.TPMPTPermanent {
			return PermanentFlags(p.Value), nil
		}
	}
	return 0, fmt.Errorf("TPM_PT_PERMANENT not returned")
}

// u32ToString decodes a big-endian 4-byte vendor string fragment.
func u32ToString(v uint32) string {
	return string([]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
