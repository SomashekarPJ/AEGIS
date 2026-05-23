package monitoring

import (
	"strings"
	"sync"
	"time"

	"aegiscore/pkg/config"
)

// ThreatAlert represents a parsed security incident alert
type ThreatAlert struct {
	Timestamp time.Time `json:"timestamp"`
	SandboxID string    `json:"sandbox_id"`
	Severity  string    `json:"severity"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	RuleName  string    `json:"rule_name"`
	Details   string    `json:"details"`
}

// SandboxBehaviorTracker monitors dynamic telemetry for behavior pattern detection
type SandboxBehaviorTracker struct {
	SandboxID       string
	Policy          *config.Policy
	SyscallHistory  []string
	ConsecutiveByp  int
	EgressAttempts  []string
	SpawnedProcs    []string
	CurrentRisk     int
	ViolationsCount int
	mutex           sync.RWMutex
}

// ThreatEngine evaluates global threat matrices
type ThreatEngine struct {
	trackers map[string]*SandboxBehaviorTracker
	mutex    sync.RWMutex
}

// NewThreatEngine creates an anomaly detection engine
func NewThreatEngine() *ThreatEngine {
	return &ThreatEngine{
		trackers: make(map[string]*SandboxBehaviorTracker),
	}
}

// RegisterSandbox sets up a tracking scorecard for a sandbox
func (te *ThreatEngine) RegisterSandbox(sandboxID string, policy *config.Policy) *SandboxBehaviorTracker {
	te.mutex.Lock()
	defer te.mutex.Unlock()

	tracker := &SandboxBehaviorTracker{
		SandboxID:      sandboxID,
		Policy:         policy,
		SyscallHistory: make([]string, 0),
		EgressAttempts: make([]string, 0),
		SpawnedProcs:   make([]string, 0),
		CurrentRisk:    0,
	}

	te.trackers[sandboxID] = tracker
	return tracker
}

// AnalyzeSyscall examines a system call trace, updates risk score, and triggers defense mitigations
// Returns: (isViolation, riskScore, alertAction)
func (te *ThreatEngine) AnalyzeSyscall(sandboxID string, syscallName string, pathOrDomain string) (bool, int, *ThreatAlert) {
	te.mutex.RLock()
	tracker, exists := te.trackers[sandboxID]
	te.mutex.RUnlock()

	if !exists {
		return false, 0, nil
	}

	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()

	tracker.SyscallHistory = append(tracker.SyscallHistory, syscallName)
	if len(tracker.SyscallHistory) > 50 {
		tracker.SyscallHistory = tracker.SyscallHistory[1:]
	}

	// 1. Filesystem Policy Verification
	if syscallName == "openat" || syscallName == "open" || syscallName == "read" {
		access := tracker.Policy.CheckFilesystemAccess(pathOrDomain)
		if access == "deny" {
			tracker.ViolationsCount++
			tracker.CurrentRisk += 25
			if tracker.CurrentRisk > 100 {
				tracker.CurrentRisk = 100
			}

			alert := &ThreatAlert{
				Timestamp: time.Now(),
				SandboxID: sandboxID,
				Severity:  "HIGH",
				RuleName:  "UNAUTHORIZED_FILE_ACCESS",
				Details:   "Attempted file read bypass on restricted folder: " + pathOrDomain,
			}
			return true, tracker.CurrentRisk, alert
		}
	}

	// 2. Syscall Blocklist Verification
	if !tracker.Policy.IsSyscallAllowed(syscallName) {
		tracker.ViolationsCount++
		tracker.CurrentRisk += 15
		if tracker.CurrentRisk > 100 {
			tracker.CurrentRisk = 100
		}

		alert := &ThreatAlert{
			Timestamp: time.Now(),
			SandboxID: sandboxID,
			Severity:  "HIGH",
			RuleName:  "FORBIDDEN_SYSCALL_TRIGGERED",
			Details:   "Syscall blocked by seccomp filter: " + syscallName,
		}
		return true, tracker.CurrentRisk, alert
	}

	// 3. Network Outbound Egress Check
	if syscallName == "connect" || syscallName == "socket" {
		if pathOrDomain != "" && !tracker.Policy.IsNetworkDomainAllowed(pathOrDomain) {
			tracker.ViolationsCount++
			tracker.CurrentRisk += 35
			if tracker.CurrentRisk > 100 {
				tracker.CurrentRisk = 100
			}

			tracker.EgressAttempts = append(tracker.EgressAttempts, pathOrDomain)

			alert := &ThreatAlert{
				Timestamp: time.Now(),
				SandboxID: sandboxID,
				Severity:  "CRITICAL",
				RuleName:  "NETWORK_BEACONING_DETECTION",
				Details:   "Blocked unauthorized egress traffic attempt to: " + pathOrDomain,
			}
			return true, tracker.CurrentRisk, alert
		}
	}

	// 4. Abnormal Subprocesses Check (e.g. fork/execve)
	if syscallName == "clone" || syscallName == "execve" {
		if pathOrDomain != "" && (strings.Contains(pathOrDomain, "sh") || strings.Contains(pathOrDomain, "bash") || strings.Contains(pathOrDomain, "nc")) {
			tracker.ViolationsCount++
			tracker.CurrentRisk += 30
			if tracker.CurrentRisk > 100 {
				tracker.CurrentRisk = 100
			}

			tracker.SpawnedProcs = append(tracker.SpawnedProcs, pathOrDomain)

			alert := &ThreatAlert{
				Timestamp: time.Now(),
				SandboxID: sandboxID,
				Severity:  "HIGH",
				RuleName:  "PROCESS_HIJACK_ATTEMPT",
				Details:   "Abnormal shell execution spawned from within guest context: " + pathOrDomain,
			}
			return true, tracker.CurrentRisk, alert
		}
	}

	return false, tracker.CurrentRisk, nil
}

// GetTracker retrieves behavioral tracking stats for a sandbox
func (te *ThreatEngine) GetTracker(sandboxID string) *SandboxBehaviorTracker {
	te.mutex.RLock()
	defer te.mutex.RUnlock()
	return te.trackers[sandboxID]
}

// DeregisterSandbox cleans up mapping data
func (te *ThreatEngine) DeregisterSandbox(sandboxID string) {
	te.mutex.Lock()
	defer te.mutex.Unlock()
	delete(te.trackers, sandboxID)
}
