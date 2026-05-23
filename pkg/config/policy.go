package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SandboxConfig defines the metadata of the sandbox
type SandboxConfig struct {
	Name string `yaml:"name" json:"name"`
}

// FilesystemConfig defines filesystem isolation directories
type FilesystemConfig struct {
	ReadOnly []string `yaml:"read_only" json:"read_only"`
	Deny     []string `yaml:"deny" json:"deny"`
	Allow    []string `yaml:"allow" json:"allow"` // Allowed paths outside standard mounts
}

// NetworkConfig defines networking capabilities
type NetworkConfig struct {
	Allow []string `yaml:"allow" json:"allow"` // Domains or IP ranges allowed
}

// ResourcesConfig defines cgroups limits
type ResourcesConfig struct {
	Memory string  `yaml:"memory" json:"memory"` // e.g. "256MB" or "1GB"
	CPU    float64 `yaml:"cpu" json:"cpu"`       // e.g. 1.5 cores
	Disk   string  `yaml:"disk" json:"disk"`     // e.g. "500MB"
}

// SyscallsConfig defines seccomp filters
type SyscallsConfig struct {
	Deny []string `yaml:"deny" json:"deny"`
}

// ExecutionConfig defines runtime parameters
type ExecutionConfig struct {
	Timeout string `yaml:"timeout" json:"timeout"` // e.g. "60s"
}

// Policy defines the structured declarative YAML blueprint
type Policy struct {
	Sandbox    SandboxConfig    `yaml:"sandbox" json:"sandbox"`
	Filesystem FilesystemConfig `yaml:"filesystem" json:"filesystem"`
	Network    NetworkConfig    `yaml:"network" json:"network"`
	Resources  ResourcesConfig  `yaml:"resources" json:"resources"`
	Syscalls   SyscallsConfig   `yaml:"syscalls" json:"syscalls"`
	Execution  ExecutionConfig  `yaml:"execution" json:"execution"`
}

// DefaultPolicy provides ultra-safe fallback controls
func DefaultPolicy() *Policy {
	return &Policy{
		Sandbox: SandboxConfig{
			Name: "default-sandbox",
		},
		Filesystem: FilesystemConfig{
			ReadOnly: []string{"/usr", "/bin", "/lib", "/lib64"},
			Deny:     []string{"/etc/shadow", "/etc/sudoers", "/home", "/root"},
		},
		Resources: ResourcesConfig{
			Memory: "512MB",
			CPU:    1.0,
			Disk:   "200MB",
		},
		Syscalls: SyscallsConfig{
			Deny: []string{"ptrace", "reboot", "syslog", "mount", "unshare", "kexec_load"},
		},
		Execution: ExecutionConfig{
			Timeout: "30s",
		},
	}
}

// LoadPolicy parses a security YAML policy file
func LoadPolicy(path string) (*Policy, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open policy file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy content: %w", err)
	}

	policy := DefaultPolicy()
	if err := yaml.Unmarshal(data, policy); err != nil {
		return nil, fmt.Errorf("failed to parse yaml policy: %w", err)
	}

	return policy, nil
}

// ParseTimeout converts the execution timeout string to time.Duration
func (p *Policy) ParseTimeout() time.Duration {
	if p.Execution.Timeout == "" {
		return 30 * time.Second
	}
	d, err := time.ParseDuration(p.Execution.Timeout)
	if err != nil {
		return 30 * time.Second
	}
	return d
}

// CheckFilesystemAccess verifies whether a path is allowed, read-only, or denied
// Returns: "deny", "read_only", or "allow"
func (p *Policy) CheckFilesystemAccess(targetPath string) string {
	cleanTarget := filepath.Clean(targetPath)

	// Deny has the highest precedence
	for _, block := range p.Filesystem.Deny {
		if strings.HasPrefix(cleanTarget, filepath.Clean(block)) {
			return "deny"
		}
	}

	// Then Read-only checks
	for _, ro := range p.Filesystem.ReadOnly {
		if strings.HasPrefix(cleanTarget, filepath.Clean(ro)) {
			return "read_only"
		}
	}

	// Defaults to allowed for other paths, but standard micro-sandboxes restrict write-access
	return "allow"
}

// IsSyscallAllowed checks if a syscall is explicitly denied in policy
func (p *Policy) IsSyscallAllowed(syscallName string) bool {
	for _, denied := range p.Syscalls.Deny {
		if strings.EqualFold(denied, syscallName) {
			return false
		}
	}
	return true
}

// IsNetworkDomainAllowed checks if a host/domain is on the allowed egress checklist
func (p *Policy) IsNetworkDomainAllowed(host string) bool {
	if len(p.Network.Allow) == 0 {
		return false // Absolute zero-trust network boundary by default
	}

	for _, domain := range p.Network.Allow {
		if domain == "*" {
			return true // Full internet egress permitted
		}
		// Match exact domain or subdomains
		if strings.EqualFold(host, domain) || strings.HasSuffix(strings.ToLower(host), "."+strings.ToLower(domain)) {
			return true
		}
	}
	return false
}
