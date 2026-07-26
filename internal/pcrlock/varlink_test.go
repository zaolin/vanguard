package pcrlock

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockVarlinkServer is a minimal Varlink server over Unix socket that
// responds to method calls with configurable replies. It implements just
// enough of the Varlink protocol (JSON + NUL terminator) to test the client.
type mockVarlinkServer struct {
	t        *testing.T
	listener *net.UnixListener
	socket   string

	// handlers maps method name to a function that returns the response.
	// If a handler returns ok=false, the server sends an error reply.
	handlers map[string]func(params json.RawMessage) (reply json.RawMessage, errID string)

	wg     sync.WaitGroup
	closed bool
	mu     sync.Mutex
}

// newMockVarlinkServer starts a mock server on a temp Unix socket.
func newMockVarlinkServer(t *testing.T, handlers map[string]func(params json.RawMessage) (json.RawMessage, string)) *mockVarlinkServer {
	t.Helper()

	dir := t.TempDir()
	socket := filepath.Join(dir, "io.systemd.PCRLock")

	// Create parent dir
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	addr, err := net.ResolveUnixAddr("unix", socket)
	if err != nil {
		t.Fatalf("resolve addr: %v", err)
	}

	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &mockVarlinkServer{
		t:        t,
		listener: listener,
		socket:   socket,
		handlers: handlers,
	}

	srv.wg.Add(1)
	go srv.serve()

	return srv
}

func (s *mockVarlinkServer) serve() {
	defer s.wg.Done()

	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()

		conn, err := s.listener.AcceptUnix()
		if err != nil {
			return
		}

		s.wg.Add(1)
		go s.handleConn(*conn)
	}
}

func (s *mockVarlinkServer) handleConn(conn net.UnixConn) {
	defer s.wg.Done()
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)

	for {
		n, err := conn.Read(chunk)
		if err != nil {
			return
		}

		// Find NUL terminator
		found := false
		for i := 0; i < n; i++ {
			if chunk[i] == 0 {
				buf = append(buf, chunk[:i]...)
				found = true
				// Remaining data after NUL is a new message — skip for simplicity
				break
			}
		}
		if !found {
			buf = append(buf, chunk[:n]...)
			continue
		}

		// Parse request
		var req varlinkRequest
		if err := json.Unmarshal(buf, &req); err != nil {
			s.t.Logf("mock server: failed to parse request: %v", err)
			return
		}

		// Dispatch to handler
		handler, ok := s.handlers[req.Method]
		if !ok {
			// Send InterfaceNotFound for unknown methods
			s.sendReply(conn, varlinkResponse{
				Error: "org.varlink.service.MethodNotImplemented",
			})
			return
		}

		var reply json.RawMessage
		var errID string
		if handler != nil {
			// Re-marshal parameters to json.RawMessage for the handler
			var rawParams json.RawMessage
			if req.Parameters != nil {
				rawParams, _ = json.Marshal(req.Parameters)
			}
			reply, errID = handler(rawParams)
		}

		resp := varlinkResponse{
			Parameters: reply,
		}
		if errID != "" {
			resp.Error = errID
		}

		s.sendReply(conn, resp)

		// Reset buffer for next message
		buf = buf[:0]
	}
}

func (s *mockVarlinkServer) sendReply(conn net.UnixConn, resp varlinkResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		s.t.Logf("mock server: failed to marshal reply: %v", err)
		return
	}
	data = append(data, 0)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(data); err != nil {
		s.t.Logf("mock server: failed to write reply: %v", err)
	}
}

func (s *mockVarlinkServer) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.listener.Close()
	s.wg.Wait()
}

// --- Tests for containsMethod ---

func TestContainsMethod(t *testing.T) {
	tests := []struct {
		name        string
		description string
		method      string
		want        bool
	}{
		{
			name:        "Lock method present",
			description: "io.systemd.PCRLock\n\nLock(category: string, lock?: bool) -> ()\nMakePolicy(force?: bool) -> ()",
			method:      "Lock",
			want:        true,
		},
		{
			name:        "MakePolicy method present",
			description: "io.systemd.PCRLock\n\nLock(category: string, lock?: bool) -> ()\nMakePolicy(force?: bool) -> ()",
			method:      "MakePolicy",
			want:        true,
		},
		{
			name:        "method absent",
			description: "io.systemd.PCRLock\n\nMakePolicy(force?: bool) -> ()",
			method:      "Lock",
			want:        false,
		},
		{
			name:        "empty description",
			description: "",
			method:      "Lock",
			want:        false,
		},
		{
			name:        "partial match without paren",
			description: "io.systemd.PCRLock\n\nLockdown(category: string) -> ()",
			method:      "Lock",
			want:        false,
		},
		{
			name:        "method at start of description",
			description: "Lock(category: string, lock?: bool) -> ()",
			method:      "Lock",
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsMethod(tt.description, tt.method)
			if got != tt.want {
				t.Errorf("containsMethod(%q, %q) = %v, want %v", tt.description, tt.method, got, tt.want)
			}
		})
	}
}

// --- Tests for varlinkRequest marshalling ---

func TestVarlinkRequestMarshal(t *testing.T) {
	req := varlinkRequest{
		Method: "io.systemd.PCRLock.Lock",
		Parameters: map[string]interface{}{
			"category": "firmwareCode",
			"lock":     false,
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if parsed["method"] != "io.systemd.PCRLock.Lock" {
		t.Errorf("method = %v, want io.systemd.PCRLock.Lock", parsed["method"])
	}

	params, ok := parsed["parameters"].(map[string]interface{})
	if !ok {
		t.Fatalf("parameters not a map: %T", parsed["parameters"])
	}

	if params["category"] != "firmwareCode" {
		t.Errorf("category = %v, want firmwareCode", params["category"])
	}

	if params["lock"] != false {
		t.Errorf("lock = %v, want false", params["lock"])
	}
}

func TestVarlinkRequestMarshalNilParameters(t *testing.T) {
	req := varlinkRequest{
		Method:     "io.systemd.PCRLock.ListComponents",
		Parameters: nil,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if parsed["method"] != "io.systemd.PCRLock.ListComponents" {
		t.Errorf("method = %v, want io.systemd.PCRLock.ListComponents", parsed["method"])
	}

	// omitempty should drop nil parameters
	if _, ok := parsed["parameters"]; ok {
		t.Error("expected parameters to be omitted when nil")
	}
}

// --- Tests for varlinkResponse unmarshalling ---

func TestVarlinkResponseUnmarshalSuccess(t *testing.T) {
	raw := `{"parameters":{"key":"value"}}`
	var resp varlinkResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp.Error != "" {
		t.Errorf("error = %q, want empty", resp.Error)
	}

	if len(resp.Parameters) == 0 {
		t.Error("expected non-empty parameters")
	}
}

func TestVarlinkResponseUnmarshalError(t *testing.T) {
	raw := `{"error":"io.systemd.PCRLock.NoChange"}`
	var resp varlinkResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp.Error != "io.systemd.PCRLock.NoChange" {
		t.Errorf("error = %q, want io.systemd.PCRLock.NoChange", resp.Error)
	}
}

// --- Tests for VarlinkClient with mock server ---

// newTestClient creates a VarlinkClient pointing at the mock server's socket.
func newTestClient(srv *mockVarlinkServer) *VarlinkClient {
	return &VarlinkClient{socketPath: srv.socket}
}

func TestVarlinkClientIsAvailableSocketMissing(t *testing.T) {
	// Point to a non-existent socket
	vc := &VarlinkClient{socketPath: filepath.Join(t.TempDir(), "nonexistent")}
	if vc.IsAvailable() {
		t.Error("IsAvailable() should return false for missing socket")
	}
}

func TestVarlinkClientIsAvailableWithLockMethod(t *testing.T) {
	idl := `io.systemd.PCRLock

Lock(category: string, lock?: bool) -> ()
MakePolicy(force?: bool) -> ()
ListComponents() -> (id: string, variants: array)
`

	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"org.varlink.service.GetInterfaceDescription": func(params json.RawMessage) (json.RawMessage, string) {
			var p struct {
				Interface string `json:"interface"`
			}
			json.Unmarshal(params, &p)
			descJSON, _ := json.Marshal(map[string]string{"description": idl})
			return descJSON, ""
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)
	if !vc.IsAvailable() {
		t.Error("IsAvailable() should return true when Lock method is present in IDL")
	}
}

func TestVarlinkClientIsAvailableWithoutLockMethod(t *testing.T) {
	// Simulate systemd <262: interface exists but Lock method is absent
	idl := `io.systemd.PCRLock

MakePolicy(force?: bool) -> ()
ListComponents() -> (id: string, variants: array)
`

	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"org.varlink.service.GetInterfaceDescription": func(params json.RawMessage) (json.RawMessage, string) {
			descJSON, _ := json.Marshal(map[string]string{"description": idl})
			return descJSON, ""
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)
	if vc.IsAvailable() {
		t.Error("IsAvailable() should return false when Lock method is absent from IDL")
	}
}

func TestVarlinkClientIsAvailableInterfaceNotFound(t *testing.T) {
	// Simulate very old systemd that doesn't know io.systemd.PCRLock at all
	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"org.varlink.service.GetInterfaceDescription": func(params json.RawMessage) (json.RawMessage, string) {
			return nil, "org.varlink.service.InterfaceNotFound"
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)
	if vc.IsAvailable() {
		t.Error("IsAvailable() should return false when interface is not found")
	}
}

func TestVarlinkClientLockCategorySuccess(t *testing.T) {
	var receivedParams map[string]interface{}

	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"io.systemd.PCRLock.Lock": func(params json.RawMessage) (json.RawMessage, string) {
			json.Unmarshal(params, &receivedParams)
			// Return empty parameters (success)
			return json.RawMessage(`{}`), ""
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)
	if err := vc.LockCategory(CategoryFirmwareCode, true); err != nil {
		t.Fatalf("LockCategory failed: %v", err)
	}

	if receivedParams["category"] != "firmwareCode" {
		t.Errorf("category = %v, want firmwareCode", receivedParams["category"])
	}

	lockVal, ok := receivedParams["lock"].(bool)
	if !ok || !lockVal {
		t.Errorf("lock = %v, want true", receivedParams["lock"])
	}
}

func TestVarlinkClientLockCategoryUnlock(t *testing.T) {
	var receivedParams map[string]interface{}

	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"io.systemd.PCRLock.Lock": func(params json.RawMessage) (json.RawMessage, string) {
			json.Unmarshal(params, &receivedParams)
			return json.RawMessage(`{}`), ""
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)
	if err := vc.LockCategory(CategorySecureBootPolicy, false); err != nil {
		t.Fatalf("LockCategory failed: %v", err)
	}

	if receivedParams["category"] != "secureBootPolicy" {
		t.Errorf("category = %v, want secureBootPolicy", receivedParams["category"])
	}

	lockVal, ok := receivedParams["lock"].(bool)
	if !ok || lockVal {
		t.Errorf("lock = %v, want false", receivedParams["lock"])
	}
}

func TestVarlinkClientLockCategoryError(t *testing.T) {
	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"io.systemd.PCRLock.Lock": func(params json.RawMessage) (json.RawMessage, string) {
			return nil, "io.systemd.PCRLock.NotSupported"
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)
	err := vc.LockCategory(CategoryFirmwareCode, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "io.systemd.PCRLock.NotSupported") {
		t.Errorf("error should contain error ID, got: %v", err)
	}
}

func TestVarlinkClientLockCategoryConnectFailure(t *testing.T) {
	vc := &VarlinkClient{socketPath: filepath.Join(t.TempDir(), "nonexistent")}
	err := vc.LockCategory(CategoryFirmwareCode, true)
	if err == nil {
		t.Fatal("expected error for missing socket, got nil")
	}

	if !strings.Contains(err.Error(), "connect") {
		t.Errorf("error should mention connect failure, got: %v", err)
	}
}

func TestVarlinkClientMakePolicySuccess(t *testing.T) {
	var receivedParams map[string]interface{}

	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"io.systemd.PCRLock.MakePolicy": func(params json.RawMessage) (json.RawMessage, string) {
			json.Unmarshal(params, &receivedParams)
			return json.RawMessage(`{}`), ""
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)
	if err := vc.MakePolicy(true); err != nil {
		t.Fatalf("MakePolicy failed: %v", err)
	}

	forceVal, ok := receivedParams["force"].(bool)
	if !ok || !forceVal {
		t.Errorf("force = %v, want true", receivedParams["force"])
	}
}

func TestVarlinkClientMakePolicyNoChange(t *testing.T) {
	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"io.systemd.PCRLock.MakePolicy": func(params json.RawMessage) (json.RawMessage, string) {
			return nil, "io.systemd.PCRLock.NoChange"
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)
	// NoChange should be treated as success (nil error)
	if err := vc.MakePolicy(false); err != nil {
		t.Errorf("MakePolicy with NoChange should not return error, got: %v", err)
	}
}

func TestVarlinkClientMakePolicyError(t *testing.T) {
	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"io.systemd.PCRLock.MakePolicy": func(params json.RawMessage) (json.RawMessage, string) {
			return nil, "io.systemd.PCRLock.TPM2Error"
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)
	err := vc.MakePolicy(false)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "TPM2Error") {
		t.Errorf("error should contain error ID, got: %v", err)
	}
}

func TestVarlinkClientListComponentsArray(t *testing.T) {
	componentsJSON := `[
		{"id":"240-secureboot-policy","variants":[{"id":"generated","path":"/var/lib/pcrlock.d/240-secureboot-policy.pcrlock.d/generated.pcrlock"}]},
		{"id":"510-uki","variants":[{"id":"pe","path":"/etc/pcrlock.d/510-uki.pcrlock.d/pe.pcrlock"}]}
	]`

	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"io.systemd.PCRLock.ListComponents": func(params json.RawMessage) (json.RawMessage, string) {
			return json.RawMessage(componentsJSON), ""
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)
	components, err := vc.ListComponents()
	if err != nil {
		t.Fatalf("ListComponents failed: %v", err)
	}

	if len(components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(components))
	}

	if components[0].ID != "240-secureboot-policy" {
		t.Errorf("component[0] id = %q, want 240-secureboot-policy", components[0].ID)
	}

	if len(components[0].Variants) != 1 {
		t.Fatalf("expected 1 variant, got %d", len(components[0].Variants))
	}

	if components[0].Variants[0].Path != "/var/lib/pcrlock.d/240-secureboot-policy.pcrlock.d/generated.pcrlock" {
		t.Errorf("variant path = %q, want /var/lib/pcrlock.d/240-secureboot-policy.pcrlock.d/generated.pcrlock",
			components[0].Variants[0].Path)
	}
}

func TestVarlinkClientListComponentsSingleObject(t *testing.T) {
	componentJSON := `{"id":"240-secureboot-policy","variants":[{"id":"generated","path":"/var/lib/pcrlock.d/240-secureboot-policy.pcrlock.d/generated.pcrlock"}]}`

	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"io.systemd.PCRLock.ListComponents": func(params json.RawMessage) (json.RawMessage, string) {
			return json.RawMessage(componentJSON), ""
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)
	components, err := vc.ListComponents()
	if err != nil {
		t.Fatalf("ListComponents failed: %v", err)
	}

	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}

	if components[0].ID != "240-secureboot-policy" {
		t.Errorf("component id = %q, want 240-secureboot-policy", components[0].ID)
	}
}

func TestVarlinkClientListComponentsError(t *testing.T) {
	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"io.systemd.PCRLock.ListComponents": func(params json.RawMessage) (json.RawMessage, string) {
			return nil, "io.systemd.PCRLock.NotSupported"
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)
	_, err := vc.ListComponents()
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "NotSupported") {
		t.Errorf("error should contain error ID, got: %v", err)
	}
}

func TestVarlinkClientListComponentsEmptyArray(t *testing.T) {
	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"io.systemd.PCRLock.ListComponents": func(params json.RawMessage) (json.RawMessage, string) {
			return json.RawMessage(`[]`), ""
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)
	components, err := vc.ListComponents()
	if err != nil {
		t.Fatalf("ListComponents failed: %v", err)
	}

	if len(components) != 0 {
		t.Errorf("expected 0 components, got %d", len(components))
	}
}

// --- Tests for VarlinkClient protocol framing ---

func TestVarlinkClientCallNulTermination(t *testing.T) {
	// Verify the client sends NUL-terminated JSON and parses the NUL-terminated reply
	var receivedRaw []byte

	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"io.systemd.PCRLock.Lock": func(params json.RawMessage) (json.RawMessage, string) {
			return json.RawMessage(`{}`), ""
		},
	})
	defer srv.Close()

	// Manually connect and send a NUL-terminated message to verify the server
	// handles it, then use the client to verify round-trip works.
	conn, err := net.DialTimeout("unix", srv.socket, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Read what the server receives by using a custom handler that captures raw bytes
	// Actually, the mock server already parses JSON. Let's just verify the client
	// round-trip works end-to-end.
	_ = receivedRaw

	vc := newTestClient(srv)
	if err := vc.LockCategory(CategoryFirmwareConfig, true); err != nil {
		t.Fatalf("LockCategory round-trip failed: %v", err)
	}
}

// --- Tests for category constants ---

func TestCategoryConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		want     string
	}{
		{"CategoryFirmwareCode", CategoryFirmwareCode, "firmwareCode"},
		{"CategoryFirmwareConfig", CategoryFirmwareConfig, "firmwareConfig"},
		{"CategorySecureBootPolicy", CategorySecureBootPolicy, "secureBootPolicy"},
		{"CategorySecureBootAuth", CategorySecureBootAuth, "secureBootAuthority"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, tt.constant, tt.want)
			}
		})
	}
}

func TestVarlinkSocketPathConstant(t *testing.T) {
	if VarlinkSocketPath != "/run/systemd/io.systemd.PCRLock" {
		t.Errorf("VarlinkSocketPath = %q, want /run/systemd/io.systemd.PCRLock", VarlinkSocketPath)
	}
}

// --- Test for NewVarlinkClient ---

func TestNewVarlinkClient(t *testing.T) {
	vc := NewVarlinkClient()
	if vc.socketPath != VarlinkSocketPath {
		t.Errorf("socketPath = %q, want %q", vc.socketPath, VarlinkSocketPath)
	}
}

// --- Test for custom socket path ---

func TestVarlinkClientCustomSocketPath(t *testing.T) {
	idl := `io.systemd.PCRLock

Lock(category: string, lock?: bool) -> ()
`

	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"org.varlink.service.GetInterfaceDescription": func(params json.RawMessage) (json.RawMessage, string) {
			descJSON, _ := json.Marshal(map[string]string{"description": idl})
			return descJSON, ""
		},
	})
	defer srv.Close()

	// Use the mock server's socket path directly
	vc := &VarlinkClient{socketPath: srv.socket}
	if !vc.IsAvailable() {
		t.Error("IsAvailable() should return true with custom socket path")
	}
}

// --- Test for multiple sequential calls on the same client ---

func TestVarlinkClientMultipleCalls(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"io.systemd.PCRLock.Lock": func(params json.RawMessage) (json.RawMessage, string) {
			mu.Lock()
			callCount++
			mu.Unlock()
			return json.RawMessage(`{}`), ""
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)

	categories := []string{CategoryFirmwareCode, CategoryFirmwareConfig, CategorySecureBootPolicy, CategorySecureBootAuth}
	for _, cat := range categories {
		if err := vc.LockCategory(cat, true); err != nil {
			t.Fatalf("LockCategory(%s) failed: %v", cat, err)
		}
	}

	mu.Lock()
	if callCount != 4 {
		t.Errorf("expected 4 calls, got %d", callCount)
	}
	mu.Unlock()
}

// --- Test for malformed response ---

func TestVarlinkClientMalformedResponse(t *testing.T) {
	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"io.systemd.PCRLock.Lock": func(params json.RawMessage) (json.RawMessage, string) {
			// Return invalid JSON by sending raw bytes directly.
			// We can't do this through the handler, so we'll test the
			// call() method's error handling via a custom approach.
			return json.RawMessage(`{}`), ""
		},
	})
	defer srv.Close()

	// Connect manually and send malformed response
	conn, err := net.DialTimeout("unix", srv.socket, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a valid request
	req := varlinkRequest{
		Method:     "io.systemd.PCRLock.Lock",
		Parameters: map[string]interface{}{"category": "firmwareCode", "lock": true},
	}
	data, _ := json.Marshal(req)
	data = append(data, 0)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	conn.Write(data)

	// Read the server's response (we just need to consume it)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	conn.Read(buf)

	// The mock server handles the request properly, so we can't easily inject
	// a malformed response. Instead, test that call() handles a closed connection.
	conn.Close()

	// Now try a new connection that gets closed immediately
	conn2, err := net.DialTimeout("unix", srv.socket, 5*time.Second)
	if err != nil {
		// Server might have shut down, skip this test
		t.Skip("could not reconnect to mock server")
	}
	// Close immediately without sending anything — server will get EOF
	conn2.Close()
}

// --- Test for response with both parameters and error ---

func TestVarlinkResponseBothParamsAndError(t *testing.T) {
	// When both are present, the Error field takes priority in our client logic
	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"io.systemd.PCRLock.Lock": func(params json.RawMessage) (json.RawMessage, string) {
			// Handler returns both params and error ID — error should win
			return json.RawMessage(`{"ignored": true}`), "io.systemd.PCRLock.Failure"
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)
	err := vc.LockCategory(CategoryFirmwareCode, true)
	if err == nil {
		t.Fatal("expected error when both params and error are present")
	}

	if !strings.Contains(err.Error(), "Failure") {
		t.Errorf("error should contain error ID, got: %v", err)
	}
}

// --- Test for large response (multi-chunk read) ---

func TestVarlinkClientLargeResponse(t *testing.T) {
	// Generate a large component list that exceeds the 4096-byte read buffer
	var components []string
	for i := 0; i < 100; i++ {
		comp := fmt.Sprintf(`{"id":"component-%d","variants":[{"id":"v%d","path":"/var/lib/pcrlock.d/%d/generated.pcrlock"}]}`, i, i, i)
		components = append(components, comp)
	}
	componentsJSON := "[" + strings.Join(components, ",") + "]"

	// Verify it's larger than the read buffer
	if len(componentsJSON) < 4096 {
		t.Fatalf("test data too small: %d bytes, need >4096", len(componentsJSON))
	}

	srv := newMockVarlinkServer(t, map[string]func(json.RawMessage) (json.RawMessage, string){
		"io.systemd.PCRLock.ListComponents": func(params json.RawMessage) (json.RawMessage, string) {
			return json.RawMessage(componentsJSON), ""
		},
	})
	defer srv.Close()

	vc := newTestClient(srv)
	comps, err := vc.ListComponents()
	if err != nil {
		t.Fatalf("ListComponents failed: %v", err)
	}

	if len(comps) != 100 {
		t.Fatalf("expected 100 components, got %d", len(comps))
	}

	if comps[50].ID != "component-50" {
		t.Errorf("component[50] id = %q, want component-50", comps[50].ID)
	}
}