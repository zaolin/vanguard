package main

import (
	"os"
	"path/filepath"
	"strings"
)

// cmdlineReader reads the kernel command line. It is a variable so the audit
// can be tested without /proc — including the read-failure case.
var cmdlineReader = func() (string, error) {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// auditKernelCmdline scans the kernel command line for parameters that weaken
// or bypass the TPM unlock. Only findings are returned; a clean command line
// produces no output.
//
// This is a pure function of the command line text so every pattern can be
// tested deterministically.
func auditKernelCmdline(text string) []mitigation {
	var findings []mitigation

	// The initrd activates test mode with a plain substring match
	// (strings.Contains in init/main.go), so anything containing "=1" after
	// the key counts — including "vanguard.testmode=10" or "x=vanguard.testmode=1".
	testMode := strings.Contains(text, "vanguard.testmode=1")
	if testMode {
		findings = append(findings, mitigation{
			Name:   "vanguard.testmode",
			Status: "critical",
			Detail: "vanguard test mode is active (the initrd matches it as a substring) — it weakens the TPM unlock in production",
			Fix:    "Remove vanguard.testmode from the boot entry",
		})
	}

	// vanguard.testhotp is only honored when test mode is ALSO active
	// (testForceHOTP checks isTestMode). Flagging it unconditionally would be
	// a false positive: alone it changes nothing.
	if strings.Contains(text, "vanguard.testhotp=1") {
		if testMode {
			findings = append(findings, mitigation{
				Name:   "vanguard.testhotp",
				Status: "critical",
				Detail: "vanguard HOTP test hook is active with test mode — the TPM unseal path is forced to fail",
				Fix:    "Remove vanguard.testhotp and vanguard.testmode from the boot entry",
			})
		} else {
			findings = append(findings, mitigation{
				Name:   "vanguard.testhotp",
				Status: "info",
				Detail: "set, but inert: it is only honored together with vanguard.testmode=1",
			})
		}
	}

	for _, field := range strings.Fields(text) {
		key, value, _ := strings.Cut(field, "=")

		switch key {
		case "vanguard.testpin":
			// Only a non-empty value embeds a usable PIN: getTestPin only
			// honours the "vanguard.testpin=" prefix with a value.
			if value != "" {
				findings = append(findings, mitigation{
					Name:   "vanguard.testpin",
					Status: "critical",
					Detail: "a TPM PIN is embedded in the kernel command line — readable by any user via /proc/cmdline",
					Fix:    "Remove vanguard.testpin= from the boot entry and change the PIN",
				})
			}

		case "vanguard.testpass":
			if value != "" {
				// getTestPass only honors this in test mode, so gate the
				// critical finding on it as well.
				if testMode {
					findings = append(findings, mitigation{
						Name:   "vanguard.testpass",
						Status: "critical",
						Detail: "a LUKS passphrase is embedded in the kernel command line with test mode active — readable by any user via /proc/cmdline",
						Fix:    "Remove vanguard.testpass= from the boot entry and change the passphrase",
					})
				} else {
					findings = append(findings, mitigation{
						Name:   "vanguard.testpass",
						Status: "info",
						Detail: "a LUKS passphrase is embedded in the kernel command line, but only used in test mode — remove it anyway",
						Fix:    "Remove vanguard.testpass= from the boot entry",
					})
				}
			}

		case "vanguard.debug":
			if value == "1" {
				findings = append(findings, mitigation{
					Name:   key,
					Status: "info",
					Detail: "verbose boot logging is enabled (writes /boot/.vanguard.log)",
				})
			}

		case "init", "rdinit":
			if value == "/bin/sh" || value == "/bin/bash" {
				findings = append(findings, mitigation{
					Name:   key,
					Status: "critical",
					Detail: key + "=" + value + " boots into a shell and skips the TPM unlock entirely",
					Fix:    "Remove the bypass parameter from the boot loader entry",
				})
			}

		case "single", "rd.break":
			findings = append(findings, mitigation{
				Name:   key,
				Status: "critical",
				Detail: key + " boots into a rescue shell and skips the TPM unlock entirely",
				Fix:    "Remove the bypass parameter from the boot loader entry",
			})

		case "debug":
			findings = append(findings, mitigation{
				Name:   "debug",
				Status: "info",
				Detail: "kernel debug logging is enabled (may expose boot details in dmesg)",
			})
		}
	}

	return findings
}

// dmiRoot is the sysfs DMI directory. It is a variable so the BIOS lookup can
// be tested with a fixture directory.
var dmiRoot = "/sys/class/dmi/id"

// readBIOSInfo reads the firmware identification from DMI/SMBIOS.
func readBIOSInfo() biosInfo {
	read := func(name string) string {
		data, err := os.ReadFile(filepath.Join(dmiRoot, name))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(data))
	}
	return biosInfo{
		Vendor:  read("bios_vendor"),
		Version: read("bios_version"),
		Date:    read("bios_date"),
		Board:   read("board_name"),
	}
}
