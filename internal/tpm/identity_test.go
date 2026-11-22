package tpm

import "testing"

// TestTPMIdentityFamily pins the vendor classification, including the
// boundaries: a real IBM TPM must NOT be called a simulator, and the
// normalized swtpm vendor string must be detected.
func TestTPMIdentityFamily(t *testing.T) {
	tests := []struct {
		name         string
		manufacturer string
		vendor       string
		want         TPMFamily
		wantFirmware bool
	}{
		{name: "Infineon", manufacturer: "IFX ", vendor: "Infineon", want: TPMFamilyInfineon},
		{name: "Intel PTT is a firmware TPM", manufacturer: "INTC", vendor: "Intel", want: TPMFamilyIntel, wantFirmware: true},
		{name: "AMD fTPM is a firmware TPM", manufacturer: "AMD ", vendor: "AMD", want: TPMFamilyAMD, wantFirmware: true},
		{name: "ST", manufacturer: "STM ", vendor: "STMicroelectronics", want: TPMFamilyST},
		{name: "Nuvoton", manufacturer: "NTC ", vendor: "Nuvoton", want: TPMFamilyNuvoton},
		{name: "swtpm with padded vendor string", manufacturer: "IBM\x00", vendor: "SW   TPM", want: TPMFamilySimulator},
		{name: "a real IBM TPM is not a simulator", manufacturer: "IBM\x00", vendor: "IBM Corp.", want: TPMFamilyUnknown},
		{name: "an unknown vendor", manufacturer: "QCOM", vendor: "Qualcomm", want: TPMFamilyUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := TPMIdentity{ManufacturerName: tc.manufacturer, VendorString: tc.vendor}
			if got := id.Family(); got != tc.want {
				t.Errorf("Family() = %s, want %s", got, tc.want)
			}
			if got := id.IsFirmwareTPM(); got != tc.wantFirmware {
				t.Errorf("IsFirmwareTPM() = %v, want %v", got, tc.wantFirmware)
			}
		})
	}
}

// TestFirmwareVersionString pins the version rendering.
func TestFirmwareVersionString(t *testing.T) {
	id := TPMIdentity{FirmwareVersion1: 1, FirmwareVersion2: 42}
	if got := id.FirmwareVersionString(); got != "1.42" {
		t.Errorf("version = %q, want 1.42", got)
	}
}
