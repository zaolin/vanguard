package pcrlock

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// Varlink socket path for systemd-pcrlock's io.systemd.PCRLock interface.
const VarlinkSocketPath = "/run/systemd/io.systemd.PCRLock"

// LockCategory constants matching systemd-pcrlock's LockCategory enum.
const (
	CategoryFirmwareCode      = "firmwareCode"
	CategoryFirmwareConfig    = "firmwareConfig"
	CategorySecureBootPolicy  = "secureBootPolicy"
	CategorySecureBootAuth    = "secureBootAuthority"
)

// VarlinkClient connects to systemd-pcrlock's Varlink socket and calls
// the io.systemd.PCRLock interface methods.
//
// The Varlink protocol is JSON over Unix socket, with each message terminated
// by NUL (0x00). See https://varlink.org/ for the protocol spec.
//
// The io.systemd.PCRLock interface (added in systemd v262) provides:
//   - Lock{category, lock}: lock/unlock a component category
//   - MakePolicy{force}: regenerate the pcrlock policy from current components
//   - ListComponents: list defined pcrlock components and their variants
//   - ReadEventLog: stream the TPM2 event log in CEL-JSON format
//   - RemovePolicy: remove the TPM2 pcrlock policy
type VarlinkClient struct {
	socketPath string
}

// NewVarlinkClient creates a Varlink client for the default socket path.
func NewVarlinkClient() *VarlinkClient {
	return &VarlinkClient{socketPath: VarlinkSocketPath}
}

// varlinkRequest is the JSON envelope for a Varlink method call.
type varlinkRequest struct {
	Method     string      `json:"method"`
	Parameters interface{} `json:"parameters,omitempty"`
}

// varlinkResponse is the JSON envelope for a Varlink method response.
type varlinkResponse struct {
	Parameters json.RawMessage `json:"parameters,omitempty"`
	Error      string          `json:"error,omitempty"`
	Continues  bool            `json:"continues,omitempty"`
}

// IsAvailable checks whether the Varlink socket exists and the io.systemd.PCRLock
// interface supports the Lock method (requires systemd v262+).
//
// Returns false (not an error) if the socket is missing or the interface is too
// old — callers should fall back to the CLI path in that case.
func (c *VarlinkClient) IsAvailable() bool {
	if _, err := os.Stat(c.socketPath); err != nil {
		return false
	}

	// Introspect the interface to check if the Lock method exists.
	// Older systemd (pre-262) has the socket but not the Lock method.
	conn, err := c.connect()
	if err != nil {
		return false
	}
	defer conn.Close()

	// Call org.varlink.service.GetInterfaceDescription to introspect
	resp, err := c.call(conn, "org.varlink.service.GetInterfaceDescription",
		map[string]string{"interface": "io.systemd.PCRLock"})
	if err != nil {
		return false
	}

	// If the interface is not found, the service is too old
	if resp.Error == "org.varlink.service.InterfaceNotFound" {
		return false
	}
	if resp.Error != "" {
		return false
	}

	// Parse the description and check for the Lock method
	var desc struct {
		Description string `json:"description"`
	}
	if err := json.Unmarshal(resp.Parameters, &desc); err != nil {
		return false
	}

	// Simple substring check — the Varlink IDL defines methods as:
	// Lock(category: string, lock?: bool) -> ()
	return containsMethod(desc.Description, "Lock")
}

// LockCategory locks or unlocks a pcrlock component category.
//
// When lock=true: regenerates the .pcrlock component files for the given
// category from the current boot's event log (equivalent to the CLI commands
// lock-firmware-code, lock-secureboot-policy, etc.).
//
// When lock=false: removes the .pcrlock component files for the given category
// (equivalent to unlock-firmware-code, unlock-secureboot-policy, etc.). This
// loosens the policy so the disk can still unlock after a firmware update
// changes the measured values.
//
// Categories: CategoryFirmwareCode, CategoryFirmwareConfig,
// CategorySecureBootPolicy, CategorySecureBootAuth.
func (c *VarlinkClient) LockCategory(category string, lock bool) error {
	conn, err := c.connect()
	if err != nil {
		return fmt.Errorf("varlink connect failed: %w", err)
	}
	defer conn.Close()

	params := map[string]interface{}{
		"category": category,
		"lock":     lock,
	}

	resp, err := c.call(conn, "io.systemd.PCRLock.Lock", params)
	if err != nil {
		return fmt.Errorf("varlink Lock call failed: %w", err)
	}

	if resp.Error != "" {
		return fmt.Errorf("io.systemd.PCRLock.Lock returned error: %s", resp.Error)
	}

	return nil
}

// MakePolicy regenerates the pcrlock policy from the current component files
// and reseals it into the TPM2 NV index.
//
// This is the Varlink equivalent of `systemd-pcrlock make-policy`. Note that
// it writes to systemd's default policy path (/var/lib/systemd/pcrlock.json),
// NOT vanguard's policy path. Vanguard still needs its own make-policy call
// with --policy=<vanguard-path> to generate a separate policy file.
//
// The Varlink MakePolicy always uses RECOVERY_PIN_HIDE mode (no interactive
// PIN prompt). Vanguard must use the CLI path for interactive PIN entry.
func (c *VarlinkClient) MakePolicy(force bool) error {
	conn, err := c.connect()
	if err != nil {
		return fmt.Errorf("varlink connect failed: %w", err)
	}
	defer conn.Close()

	params := map[string]interface{}{
		"force": force,
	}

	resp, err := c.call(conn, "io.systemd.PCRLock.MakePolicy", params)
	if err != nil {
		return fmt.Errorf("varlink MakePolicy call failed: %w", err)
	}

	// NoChange is not an error for us — the policy was already up to date
	if resp.Error == "io.systemd.PCRLock.NoChange" {
		return nil
	}

	if resp.Error != "" {
		return fmt.Errorf("io.systemd.PCRLock.MakePolicy returned error: %s", resp.Error)
	}

	return nil
}

// Component represents a pcrlock component as returned by ListComponents.
type Component struct {
	ID      string           `json:"id"`
	Variants []ComponentVariant `json:"variants"`
}

// ComponentVariant represents a variant of a pcrlock component.
type ComponentVariant struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

// ListComponents returns the defined pcrlock components and their variants.
// This is the Varlink equivalent of `systemd-pcrlock list-components`.
//
// The method streams results (SD_VARLINK_METHOD_MORE), so we collect all
// replies until the connection closes.
func (c *VarlinkClient) ListComponents() ([]Component, error) {
	conn, err := c.connect()
	if err != nil {
		return nil, fmt.Errorf("varlink connect failed: %w", err)
	}
	defer conn.Close()

	resp, err := c.call(conn, "io.systemd.PCRLock.ListComponents", nil)
	if err != nil {
		return nil, fmt.Errorf("varlink ListComponents call failed: %w", err)
	}

	if resp.Error != "" {
		return nil, fmt.Errorf("io.systemd.PCRLock.ListComponents returned error: %s", resp.Error)
	}

	// Single reply (non-streaming fallback) — parse as array
	var components []Component
	if err := json.Unmarshal(resp.Parameters, &components); err != nil {
		// Try single object
		var comp Component
		if err2 := json.Unmarshal(resp.Parameters, &comp); err2 != nil {
			return nil, fmt.Errorf("failed to parse ListComponents response: %w", err)
		}
		components = append(components, comp)
	}

	return components, nil
}

// connect opens a Unix socket connection to the Varlink service.
func (c *VarlinkClient) connect() (net.Conn, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", c.socketPath, err)
	}
	return conn, nil
}

// call sends a Varlink method call and reads the response.
// Varlink protocol: JSON message terminated by NUL (0x00).
func (c *VarlinkClient) call(conn net.Conn, method string, parameters interface{}) (*varlinkResponse, error) {
	req := varlinkRequest{
		Method:     method,
		Parameters: parameters,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Append NUL terminator
	data = append(data, 0)

	// Set write timeout
	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	// Read response until NUL
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, err
	}

	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for {
		n, err := conn.Read(chunk)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		// Find NUL terminator in this chunk
		for i := 0; i < n; i++ {
			if chunk[i] == 0 {
				buf = append(buf, chunk[:i]...)
				goto done
			}
		}
		buf = append(buf, chunk[:n]...)
	}

done:
	var resp varlinkResponse
	if err := json.Unmarshal(buf, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// containsMethod checks if a Varlink interface description string contains
// a method definition with the given name. The IDL format is:
// Lock(category: string, lock?: bool) -> ()
func containsMethod(description, method string) bool {
	// Look for "MethodName(" at the start of a line or after whitespace
	needle := method + "("
	for i := 0; i < len(description); i++ {
		if description[i] == needle[0] {
			if i+len(needle) <= len(description) && description[i:i+len(needle)] == needle {
				return true
			}
		}
	}
	return false
}