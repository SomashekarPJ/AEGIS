package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempWorkload(t *testing.T, name string, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write workload: %v", err)
	}
	return path
}

func TestIsMaliciousWorkloadAllowsCleanScript(t *testing.T) {
	path := writeTempWorkload(t, "normal.py", `print("hello from a safe file")`)

	if IsMaliciousWorkload(path) {
		t.Fatal("clean script was classified as malicious")
	}
}

func TestIsMaliciousWorkloadFlagsSuspiciousScript(t *testing.T) {
	path := writeTempWorkload(t, "normal_named_file.py", `
import os
import socket

os.system("/bin/sh -c whoami")
open("/etc/shadow").read()
socket.socket().connect(("185.220.101.5", 443))
`)

	if !IsMaliciousWorkload(path) {
		t.Fatal("suspicious script was classified as clean")
	}
}

func TestIsMaliciousWorkloadFlagsDemoMalware(t *testing.T) {
	path := filepath.Join("..", "..", "demo", "malware.py")

	if !IsMaliciousWorkload(path) {
		t.Fatal("demo malware payload was classified as clean")
	}
}

func TestIsMaliciousWorkloadDoesNotTrustNameAlone(t *testing.T) {
	path := writeTempWorkload(t, "malware-demo-name-only.py", `print("safe demo text")`)

	if IsMaliciousWorkload(path) {
		t.Fatal("filename alone should not classify a script as malicious")
	}
}

func TestIsMaliciousPDFDetectsOpenActionJavaScript(t *testing.T) {
	path := writeTempWorkload(t, "document.pdf", "%PDF-1.4\n1 0 obj\n<< /OpenAction 2 0 R /JS (eval('payload')) >>\nendobj\n")

	if !IsMaliciousWorkload(path) {
		t.Fatal("suspicious PDF action was classified as clean")
	}
}

func TestIsMaliciousPDFAllowsCleanPDF(t *testing.T) {
	path := writeTempWorkload(t, "invoice.pdf", "%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	if IsMaliciousWorkload(path) {
		t.Fatal("clean PDF was classified as malicious")
	}
}
