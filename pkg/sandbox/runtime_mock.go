//go:build !linux

package sandbox

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"aegiscore/pkg/config"
)

// MockSandbox implements the Sandbox interface for non-Linux / simulation environments
type MockSandbox struct {
	id              string
	name            string
	pid             int
	status          State
	policy          *config.Policy
	workloadPath    string
	startTime       time.Time
	cpuUsage        float64
	memoryUsage     int64
	diskUsage       int64
	riskScore       int
	violationsCount int
	stopChan        chan struct{}
	eventChan       chan interface{}
	mutex           sync.RWMutex
}

// NewMockSandbox creates a sandbox simulator
func NewMockSandbox(id string, name string, workloadPath string, policy *config.Policy, eventChan chan interface{}) *MockSandbox {
	return &MockSandbox{
		id:           id,
		name:         name,
		pid:          10000 + rand.Intn(20000),
		status:       StatePending,
		policy:       policy,
		workloadPath: workloadPath,
		stopChan:     make(chan struct{}),
		eventChan:    eventChan,
		riskScore:    0,
	}
}

func (s *MockSandbox) ID() string {
	return s.id
}

func (s *MockSandbox) Name() string {
	return s.name
}

func (s *MockSandbox) PID() int {
	return s.pid
}

func (s *MockSandbox) Status() State {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.status
}

func (s *MockSandbox) Info() *SandboxInfo {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	durationStr := "0s"
	if !s.startTime.IsZero() {
		durationStr = time.Since(s.startTime).Round(time.Second).String()
	}

	return &SandboxInfo{
		ID:              s.id,
		Name:            s.name,
		PID:             s.pid,
		Status:          s.status,
		Policy:          s.policy,
		WorkloadPath:    s.workloadPath,
		StartTime:       s.startTime,
		Duration:        durationStr,
		CPUUsage:        s.cpuUsage,
		MemoryUsage:     s.memoryUsage,
		DiskUsage:       s.diskUsage,
		RiskScore:       s.riskScore,
		ViolationsCount: s.violationsCount,
	}
}

// Start initiates the simulation run
func (s *MockSandbox) Start() error {
	s.mutex.Lock()
	s.status = StateRunning
	s.startTime = time.Now()
	s.cpuUsage = 15.4
	s.memoryUsage = 28 * 1024 * 1024 // 28MB starting
	s.diskUsage = 12 * 1024 * 1024   // 12MB starting
	s.mutex.Unlock()

	s.emitSystemEvent("INFO", "SANDBOX_INIT", "Initializing namespaces and sandbox execution structure")
	s.emitSystemEvent("INFO", "NAMESPACES_MOUNT", "Isolated mounts initialized (user, pid, net, ipc, uts namespaces active)")
	s.emitSystemEvent("INFO", "CAPABILITIES_DROP", "Dynamically dropped Linux kernel capabilities: CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_RAWIO")
	s.emitSystemEvent("INFO", "SECCOMP_APPLY", "Syscall filter active. Seccomp-BPF rules configured via libseccomp")
	s.emitSystemEvent("INFO", "CGROUPS_SETUP", fmt.Sprintf("Cgroups v2 mounted under /sys/fs/cgroup/aegis/%s. CPU Limit=%f core, Memory Limit=%s", s.id, s.policy.Resources.CPU, s.policy.Resources.Memory))

	isMalicious := IsMaliciousWorkload(s.workloadPath)
	if isMalicious {
		s.mutex.Lock()
		s.riskScore = 20
		s.mutex.Unlock()
		s.emitSystemEvent("WARNING", "STATIC_SCAN", fmt.Sprintf("Workload classifier marked %s as SUSPICIOUS. Dynamic containment telemetry armed.", filepath.Base(s.workloadPath)))
		s.emitAlertEvent("WARNING", "STATIC_ANALYSIS", "MALICIOUS_WORKLOAD_DETECTED", "Static classifier detected high-risk indicators before execution.")
	} else {
		s.emitSystemEvent("INFO", "STATIC_SCAN", fmt.Sprintf("Workload classifier marked %s as CLEAN. Monitoring benign execution only.", filepath.Base(s.workloadPath)))
	}

	if strings.HasSuffix(strings.ToLower(s.workloadPath), ".pdf") {
		if isMalicious {
			s.emitSystemEvent("INFO", "PROCESS_START", fmt.Sprintf("Opening isolated guest PDF document: %s (PID: %d) inside virtual isolated PDF reader", filepath.Base(s.workloadPath), s.pid))
		} else {
			s.emitSystemEvent("INFO", "PROCESS_START", fmt.Sprintf("Opening isolated clean guest PDF: %s (PID: %d) inside secure virtual isolated PDF viewer", filepath.Base(s.workloadPath), s.pid))
		}
	} else {
		s.emitSystemEvent("INFO", "PROCESS_START", fmt.Sprintf("Spawning sandboxed guest binary: python %s (PID: %d)", filepath.Base(s.workloadPath), s.pid))
	}

	go s.telemetrySimulationLoop()

	return nil
}

func (s *MockSandbox) Kill() error {
	s.mutex.Lock()
	if s.status == StateTerminated {
		s.mutex.Unlock()
		return nil
	}
	s.status = StateTerminated
	s.cpuUsage = 0
	s.memoryUsage = 0
	s.mutex.Unlock()

	close(s.stopChan)
	s.emitSystemEvent("WARNING", "PROCESS_TERMINATED", "SIGKILL issued to sandboxed process tree")
	s.emitSystemEvent("INFO", "CLEANUP", "Dismantling namespaces and cgroups directory structures")
	return nil
}

func (s *MockSandbox) Throtle(cpuPercent float64, memoryBytes int64) error {
	s.mutex.Lock()
	s.status = StateThrottled
	s.cpuUsage = cpuPercent
	s.memoryUsage = memoryBytes
	s.mutex.Unlock()

	s.emitSystemEvent("WARNING", "CGROUPS_THROTTLE", fmt.Sprintf("Cgroup enforcement triggered! Throttling CPU to %.1f%% and memory ceiling to %d MB", cpuPercent, memoryBytes/(1024*1024)))
	return nil
}

func (s *MockSandbox) Quarantine() error {
	s.mutex.Lock()
	s.status = StateQuarantined
	s.riskScore = 95
	s.cpuUsage = 1.0 // Frozen
	s.mutex.Unlock()

	s.emitSystemEvent("CRITICAL", "ACTIVE_QUARANTINE", "CRITICAL ANOMALY: Sandbox transitioned into Quarantine. Dynamic network ingress/egress locked down, process suspended (SIGSTOP)")
	return nil
}

func (s *MockSandbox) UpdatePolicy(newPolicy *config.Policy) error {
	s.mutex.Lock()
	s.policy = newPolicy
	s.mutex.Unlock()

	s.emitSystemEvent("INFO", "POLICY_HOT_RELOAD", "Security Policy updated on the fly. Re-applying seccomp filters and cgroups values without daemon restart")
	return nil
}

type SimulatedAttack struct {
	delay    time.Duration
	syscall  string
	action   string
	severity string
	violType string
	details  string
	riskInc  int
}

// Telemetry & Security Violation Emulation Engine
func (s *MockSandbox) telemetrySimulationLoop() {
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()

	var attacks []SimulatedAttack

	if IsMaliciousWorkload(s.workloadPath) {
		if strings.HasSuffix(strings.ToLower(s.workloadPath), ".pdf") {
			attacks = []SimulatedAttack{
				{
					delay:    4 * time.Second,
					syscall:  "sys_read",
					action:   "PDF_JS_EXECUTION",
					severity: "WARNING",
					violType: "FILESYSTEM_BREACH",
					details:  "Embedded PDF Javascript (/JS and /JavaScript streams) execution detected inside PDF virtual reader",
					riskInc:  20,
				},
				{
					delay:    8 * time.Second,
					syscall:  "openat",
					action:   "UNAUTHORIZED_FILE_ACCESS",
					severity: "HIGH",
					violType: "FILESYSTEM_BREACH",
					details:  "Attempted read access on host shadow file: /etc/passwd from PDF JS execution context",
					riskInc:  25,
				},
				{
					delay:    12 * time.Second,
					syscall:  "clone",
					action:   "SUSPICIOUS_SUBPROCESS",
					severity: "HIGH",
					violType: "EXECUTION_BREACH",
					details:  "Attempted system shell spawn via PDF reader exploit (/Launch command)",
					riskInc:  30,
				},
				{
					delay:    16 * time.Second,
					syscall:  "connect",
					action:   "NETWORK_BEACONING",
					severity: "CRITICAL",
					violType: "EGRESS_BREACH",
					details:  "Blocked PDF phishing hyperlink redirection to unapproved server: http://phishing-c2-portal.com",
					riskInc:  25,
				},
			}
		} else {
			attacks = []SimulatedAttack{
				{
					delay:    4 * time.Second,
					syscall:  "openat",
					action:   "UNAUTHORIZED_FILE_ACCESS",
					severity: "HIGH",
					violType: "FILESYSTEM_BREACH",
					details:  "Attempted read access on host shadow file: /etc/shadow",
					riskInc:  25,
				},
				{
					delay:    8 * time.Second,
					syscall:  "clone",
					action:   "SUSPICIOUS_SUBPROCESS",
					severity: "HIGH",
					violType: "EXECUTION_BREACH",
					details:  "Unauthorized child process spawn attempt: /bin/sh (interactive shell shellcode detected)",
					riskInc:  30,
				},
				{
					delay:    12 * time.Second,
					syscall:  "connect",
					action:   "NETWORK_BEACONING",
					severity: "CRITICAL",
					violType: "EGRESS_BREACH",
					details:  "Outbound network egress blocked to blacklisted IP: 185.220.101.5:443 (TOR exit node, potential C2 beaconing)",
					riskInc:  35,
				},
				{
					delay:    16 * time.Second,
					syscall:  "malloc",
					action:   "RESOURCE_EXHAUSTION",
					severity: "CRITICAL",
					violType: "QUOTA_BREACH",
					details:  "Memory consumption spike: 480MB allocated (exceeds cgroup v2 hard limit of 256MB)",
					riskInc:  10,
				},
			}
		}
	} else {
		attacks = []SimulatedAttack{}
		go func() {
			time.Sleep(2 * time.Second)
			if strings.HasSuffix(strings.ToLower(s.workloadPath), ".pdf") {
				s.emitSystemEvent("INFO", "PDF_SCAN", "Scanning PDF structures: 0 vulnerabilities or active scripts found.")
				time.Sleep(2 * time.Second)
				s.emitSystemEvent("INFO", "PDF_RENDER", "PDF pages parsed successfully. Document status: SECURE.")
			} else {
				s.emitSystemEvent("INFO", "WORKLOAD_SCAN", "Static script scan found no high-risk syscall, shell, credential, or network-beacon indicators.")
				time.Sleep(2 * time.Second)
				s.emitSystemEvent("INFO", "WORKLOAD_COMPLETE", "Clean workload remained within policy boundaries.")
			}
		}()
	}

	startTime := time.Now()
	attackIdx := 0

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.mutex.Lock()
			if s.status == StateTerminated || s.status == StateFailed {
				s.mutex.Unlock()
				return
			}

			// Generate normal system logs / syscall telemetry
			if s.status == StateRunning {
				// Oscillate metrics
				s.cpuUsage = 15.0 + rand.Float64()*10.0
				s.memoryUsage += int64(1024 * 1024 * (rand.Intn(4) - 1)) // +/- 1MB
				if s.memoryUsage < 10*1024*1024 {
					s.memoryUsage = 20 * 1024 * 1024
				}

				// Emit random benign trace
				benignSyscalls := []string{"read", "write", "epoll_wait", "getpid", "stat", "futex", "mmap"}
				randomSys := benignSyscalls[rand.Intn(len(benignSyscalls))]
				s.emitSyscallTrace(randomSys, "SUCCESS", "Standard runtime cycle execution")
			}

			// Check for scheduled security attacks
			elapsed := time.Since(startTime)
			if attackIdx < len(attacks) && elapsed >= attacks[attackIdx].delay {
				attack := attacks[attackIdx]
				attackIdx++

				// Increment risk & violation counts
				s.violationsCount++
				s.riskScore += attack.riskInc
				if s.riskScore > 100 {
					s.riskScore = 100
				}

				s.mutex.Unlock() // Unlock to emit

				// Emit syscall block and violation event
				s.emitSyscallTrace(attack.syscall, "BLOCKED", fmt.Sprintf("Violated policy restrictions: %s", attack.details))
				s.emitAlertEvent(attack.severity, attack.violType, attack.action, attack.details)

				// Active Defense actions
				s.mutex.Lock()
				if s.riskScore >= 50 && s.riskScore < 80 && s.status == StateRunning {
					s.mutex.Unlock()
					s.Throtle(5.0, 32*1024*1024) // Dynamic CGroup Throttling
					s.mutex.Lock()
				} else if s.riskScore >= 80 && s.status != StateQuarantined {
					s.mutex.Unlock()
					s.Quarantine() // Dynamic Threat Isolation & Quarantine
					s.mutex.Lock()
				}
			}

			s.mutex.Unlock()
		}
	}
}

// Telemetry structures for WebSocket feed
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	SandboxID string    `json:"sandbox_id"`
	Type      string    `json:"type"`  // "SYSCALL", "ALERT", "SYSTEM"
	Level     string    `json:"level"` // "INFO", "WARNING", "CRITICAL"
	Category  string    `json:"category"`
	Action    string    `json:"action"`
	Message   string    `json:"message"`
}

func (s *MockSandbox) emitSystemEvent(level, action, message string) {
	evt := Event{
		Timestamp: time.Now(),
		SandboxID: s.id,
		Type:      "SYSTEM",
		Level:     level,
		Category:  "DAEMON",
		Action:    action,
		Message:   message,
	}
	select {
	case s.eventChan <- evt:
	default:
	}
}

func (s *MockSandbox) emitSyscallTrace(name, status, message string) {
	evt := Event{
		Timestamp: time.Now(),
		SandboxID: s.id,
		Type:      "SYSCALL",
		Level:     "INFO",
		Category:  "KERNEL",
		Action:    name,
		Message:   fmt.Sprintf("[%s] %s", status, message),
	}
	if status == "BLOCKED" {
		evt.Level = "WARNING"
	}
	select {
	case s.eventChan <- evt:
	default:
	}
}

func (s *MockSandbox) emitAlertEvent(severity, category, action, message string) {
	level := "WARNING"
	if severity == "CRITICAL" {
		level = "CRITICAL"
	}
	evt := Event{
		Timestamp: time.Now(),
		SandboxID: s.id,
		Type:      "ALERT",
		Level:     level,
		Category:  category,
		Action:    action,
		Message:   message,
	}
	select {
	case s.eventChan <- evt:
	default:
	}
}
