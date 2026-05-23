package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"aegiscore/pkg/config"
)

type ThreatScanResult struct {
	Malicious bool     `json:"malicious"`
	Score     int      `json:"score"`
	Verdict   string   `json:"verdict"`
	Reasons   []string `json:"reasons"`
}

// hasPDFName checks if the PDF contains a specific uncompressed PDF name object followed by standard delimiters.
// This prevents false positive collisions in compressed binary streams where characters appear by chance.
func hasPDFName(content, name string) bool {
	delims := []string{" ", "\r", "\n", "/", "[", "(", "<", "{", "]", ")", ">", "}"}
	for _, d := range delims {
		if strings.Contains(content, name+d) {
			return true
		}
	}
	return false
}

func hasAny(content string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(content, needle) {
			return true
		}
	}
	return false
}

func addSignal(score *int, reasons *[]string, points int, reason string) {
	*score += points
	*reasons = append(*reasons, reason)
}

func resultFromScore(score int, reasons []string) ThreatScanResult {
	result := ThreatScanResult{
		Score:   score,
		Reasons: reasons,
		Verdict: "CLEAN",
	}
	if score >= 35 {
		result.Malicious = true
		result.Verdict = "MALICIOUS"
	} else if score > 0 {
		result.Verdict = "SUSPICIOUS"
	}
	return result
}

// IsMaliciousPDF checks if a PDF is malicious by scanning its content or file name
func IsMaliciousPDF(path string) bool {
	return AnalyzeWorkload(path).Malicious
}

func analyzePDFContent(fileName string, data []byte) ThreatScanResult {
	lowerName := strings.ToLower(filepath.Base(fileName))
	content := string(data)
	lowerContent := strings.ToLower(content)
	score := 0
	reasons := make([]string, 0)

	if strings.Contains(lowerName, "malware") ||
		strings.Contains(lowerName, "threat") ||
		strings.Contains(lowerName, "exploit") ||
		strings.Contains(lowerName, "phishing") ||
		strings.Contains(lowerName, "infected") ||
		strings.Contains(lowerName, "payload") {
		addSignal(&score, &reasons, 20, "suspicious PDF filename")
	}

	hasJS := hasPDFName(content, "/JS") || hasPDFName(content, "/JavaScript")
	if hasJS {
		addSignal(&score, &reasons, 25, "embedded PDF JavaScript action")
	}
	if hasJS && hasAny(lowerContent, "eval", "unescape", "string.fromcharcode", "activexobject", "base64", "payload", "shellcode", "heap") {
		addSignal(&score, &reasons, 30, "suspicious JavaScript exploit content")
	}

	hasLaunch := hasPDFName(content, "/Launch")
	if hasLaunch {
		addSignal(&score, &reasons, 25, "PDF launch action")
	}
	if hasLaunch && hasAny(lowerContent, "cmd", "powershell", "sh", "bash", "wscript", ".exe") {
		addSignal(&score, &reasons, 30, "external command launch from PDF")
	}

	if hasPDFName(content, "/OpenAction") && hasJS {
		addSignal(&score, &reasons, 35, "PDF auto-runs JavaScript on open")
	}

	if hasPDFName(content, "/AA") && hasJS {
		addSignal(&score, &reasons, 35, "PDF additional action executes JavaScript")
	}

	return resultFromScore(score, reasons)
}

// IsMaliciousWorkload performs static classification for uploaded workloads.
// It uses content-weighted signals so a clean script named "malware-sandbox.py"
// is not misclassified, while real suspicious uploads are identified before run.
func IsMaliciousWorkload(path string) bool {
	return AnalyzeWorkload(path).Malicious
}

func AnalyzeWorkload(path string) ThreatScanResult {
	data, err := os.ReadFile(path)
	if err != nil {
		return ThreatScanResult{Verdict: "UNKNOWN", Reasons: []string{"unable to read workload"}}
	}
	return AnalyzeWorkloadBytes(filepath.Base(path), data)
}

func AnalyzeWorkloadBytes(fileName string, data []byte) ThreatScanResult {
	lowerName := strings.ToLower(filepath.Base(fileName))
	if strings.HasSuffix(lowerName, ".pdf") || strings.HasPrefix(string(data), "%PDF") {
		return analyzePDFContent(fileName, data)
	}

	content := strings.ToLower(string(data))
	score := 0
	reasons := make([]string, 0)

	if hasAny(lowerName, "malware", "exploit", "phishing", "infected") {
		addSignal(&score, &reasons, 20, "suspicious filename")
	}
	if hasAny(content, "breach_attempt", "seccomp_block", "kernel_contain", "network_lockdown", "quarantine_lock") {
		addSignal(&score, &reasons, 35, "explicit sandbox breach or containment markers")
	}
	if hasAny(content, "privilege escalation", "credential", "keylogger", "ransomware", "trojan", "reverse shell", "meterpreter") {
		addSignal(&score, &reasons, 25, "malware behavior keywords")
	}
	if hasAny(content, "delete shadow copies", "vssadmin delete", "encrypt files", "decrypt key", "persistence", "autorun") {
		addSignal(&score, &reasons, 30, "ransomware or persistence behavior")
	}
	if hasAny(content, "eicar-standard-antivirus-test-file", "x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar") {
		addSignal(&score, &reasons, 50, "EICAR test malware signature")
	}
	if hasAny(content, "/etc/shadow", "/etc/passwd", "sam\\", "ntds.dit") {
		addSignal(&score, &reasons, 30, "credential or protected-file access")
	}
	if hasAny(content, "socket(", "connect(", "urllib.request", "requests.post", "curl ", "wget ", "http://", "https://") {
		addSignal(&score, &reasons, 20, "outbound network or download behavior")
	}
	if hasAny(content, "subprocess.", "os.system", "popen(", "/bin/sh", "bash -c", "powershell", "cmd.exe", "wscript.shell") {
		addSignal(&score, &reasons, 25, "shell or subprocess execution")
	}
	if hasAny(content, "base64.b64decode", "fromcharcode", "eval(", "exec(", "shellcode", "payload") {
		addSignal(&score, &reasons, 20, "obfuscation or dynamic code execution")
	}
	if hasAny(content, "while true", "forkbomb", ":(){ :|:& };:", "malloc", "memory flood") {
		addSignal(&score, &reasons, 15, "resource exhaustion behavior")
	}
	if hasAny(content, "185.220.101.5", "tor node", "c2", "beacon") {
		addSignal(&score, &reasons, 30, "known C2 or beaconing indicator")
	}

	return resultFromScore(score, reasons)
}

// State represents the current lifecycle of a sandbox
type State string

const (
	StatePending     State = "PENDING"
	StateRunning     State = "RUNNING"
	StateThrottled   State = "THROTTLED"
	StateQuarantined State = "QUARANTINED"
	StateTerminated  State = "TERMINATED"
	StateFailed      State = "FAILED"
)

// SandboxInfo contains general metadata and live telemetry for display and API
type SandboxInfo struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	PID             int            `json:"pid"`
	Status          State          `json:"status"`
	Policy          *config.Policy `json:"policy"`
	WorkloadPath    string         `json:"workload_path"`
	StartTime       time.Time      `json:"start_time"`
	Duration        string         `json:"duration"`
	CPUUsage        float64        `json:"cpu_usage"`    // Percentage
	MemoryUsage     int64          `json:"memory_usage"` // Bytes
	DiskUsage       int64          `json:"disk_usage"`   // Bytes
	RiskScore       int            `json:"risk_score"`   // Dynamic index (0-100)
	ViolationsCount int            `json:"violations_count"`
}

// Sandbox represents the dynamic process isolation boundary
type Sandbox interface {
	ID() string
	Name() string
	PID() int
	Status() State
	Info() *SandboxInfo
	Start() error
	Kill() error
	Throtle(cpuPercent float64, memoryBytes int64) error
	Quarantine() error
	UpdatePolicy(newPolicy *config.Policy) error
}
