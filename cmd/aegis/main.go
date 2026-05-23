package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const defaultDaemonURL = "http://localhost:8080"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	daemonURL := os.Getenv("AEGIS_DAEMON_URL")
	if daemonURL == "" {
		daemonURL = defaultDaemonURL
	}

	switch command {
	case "run":
		handleRun(daemonURL)
	case "inspect":
		handleInspect(daemonURL)
	case "logs":
		handleLogs(daemonURL)
	case "kill":
		handleKill(daemonURL)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Error: unknown command '%s'\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("AegisCore - Secure Process Isolation & Sandbox Management Framework")
	fmt.Println("\nUsage:")
	fmt.Println("  aegis <command> [arguments]")
	fmt.Println("\nCommands:")
	fmt.Println("  run <workload> [--policy <policy.yaml>] [--name <name>]   Launch an isolated sandbox workload")
	fmt.Println("  inspect <sandbox-id>                                      Inspect details of a specific sandbox")
	fmt.Println("  logs <sandbox-id>                                         Display secure audit and kernel logs")
	fmt.Println("  kill <sandbox-id>                                         Terminate process containment boundary")
	fmt.Println("\nExamples:")
	fmt.Println("  aegis run demo/malware.py --policy strict.yaml")
	fmt.Println("  aegis inspect sb-a1b2c3d4")
	fmt.Println("  aegis logs sb-a1b2c3d4")
	fmt.Println("  aegis kill sb-a1b2c3d4")
}

type SandboxInfo struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	PID             int       `json:"pid"`
	Status          string    `json:"status"`
	WorkloadPath    string    `json:"workload_path"`
	StartTime       time.Time `json:"start_time"`
	Duration        string    `json:"duration"`
	CPUUsage        float64   `json:"cpu_usage"`
	MemoryUsage     int64     `json:"memory_usage"`
	DiskUsage       int64     `json:"disk_usage"`
	RiskScore       int       `json:"risk_score"`
	ViolationsCount int       `json:"violations_count"`
}

type AuditRecord struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	SandboxID string    `json:"sandbox_id"`
	Type      string    `json:"type"`
	Level     string    `json:"level"`
	Category  string    `json:"category"`
	Action    string    `json:"action"`
	Message   string    `json:"message"`
}

func handleRun(daemonURL string) {
	if len(os.Args) < 3 {
		fmt.Println("Error: workload script/binary is required")
		fmt.Println("Usage: aegis run <workload> [--policy <policy.yaml>] [--name <name>]")
		os.Exit(1)
	}

	workload := os.Args[2]
	policyPath := ""
	name := "sb-" + time.Now().Format("05.000") // Unique default name

	// Parse custom simple arguments
	for i := 3; i < len(os.Args); i++ {
		if os.Args[i] == "--policy" && i+1 < len(os.Args) {
			policyPath = os.Args[i+1]
			i++
		}
		if os.Args[i] == "--name" && i+1 < len(os.Args) {
			name = os.Args[i+1]
			i++
		}
	}

	// Prepare payload
	reqData := map[string]string{
		"name":          name,
		"workload_path": workload,
		"policy_path":   policyPath,
	}
	jsonBytes, _ := json.Marshal(reqData)

	url := fmt.Sprintf("%s/api/sandbox/run", daemonURL)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBytes))
	if err != nil {
		fmt.Printf("Error: Failed to connect to secure daemon at %s. Ensure aegisd is active.\n", daemonURL)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Error: Server rejected run command (Status %d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	var sb SandboxInfo
	if err := json.NewDecoder(resp.Body).Decode(&sb); err != nil {
		fmt.Printf("Error: Failed to decode sandbox response: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n🛡️  AegisCore Secure Process Containment Started")
	fmt.Println("==================================================")
	fmt.Printf("Sandbox ID:      \033[1;36m%s\033[0m\n", sb.ID)
	fmt.Printf("Identifier Name: %s\n", sb.Name)
	fmt.Printf("Kernel PID:      %d\n", sb.PID)
	fmt.Printf("Workload file:   %s\n", sb.WorkloadPath)
	fmt.Printf("Lifecycle State: \033[1;32m%s\033[0m\n", sb.Status)
	fmt.Println("==================================================")
	fmt.Println("Telemetry stream successfully linked. Use 'aegis logs' or the SOC Dashboard to observe behavior.")
}

func handleInspect(daemonURL string) {
	if len(os.Args) < 3 {
		fmt.Println("Error: Sandbox ID is required")
		fmt.Println("Usage: aegis inspect <sandbox-id>")
		os.Exit(1)
	}
	targetID := os.Args[2]

	resp, err := http.Get(fmt.Sprintf("%s/api/sandboxes", daemonURL))
	if err != nil {
		fmt.Println("Error: Failed to connect to secure daemon.")
		os.Exit(1)
	}
	defer resp.Body.Close()

	var sbs []SandboxInfo
	if err := json.NewDecoder(resp.Body).Decode(&sbs); err != nil {
		fmt.Printf("Error: Failed to decode server response: %v\n", err)
		os.Exit(1)
	}

	var target *SandboxInfo
	for _, sb := range sbs {
		if strings.EqualFold(sb.ID, targetID) {
			target = &sb
			break
		}
	}

	if target == nil {
		fmt.Printf("Error: Sandbox with ID '%s' not found on this daemon node.\n", targetID)
		os.Exit(1)
	}

	fmt.Println("\n🛡️  AegisCore Infrastructure Sandbox Inspector")
	fmt.Println("==================================================")
	fmt.Printf("Sandbox ID:      \033[1;36m%s\033[0m\n", target.ID)
	fmt.Printf("Process Name:    %s\n", target.Name)
	fmt.Printf("Kernel PID:      %d\n", target.PID)
	fmt.Printf("Workload Path:   %s\n", target.WorkloadPath)
	fmt.Printf("Current State:   %s\n", target.Status)
	fmt.Printf("Execution Time:  %s\n", target.Duration)
	fmt.Println("----------------- Telemetry Dials ----------------")
	fmt.Printf("CPU Allocation:  %.2f %%\n", target.CPUUsage)
	fmt.Printf("Memory Active:   %.2f MB\n", float64(target.MemoryUsage)/(1024*1024))
	fmt.Printf("Disk Allocated:  %.2f MB\n", float64(target.DiskUsage)/(1024*1024))
	fmt.Println("----------------- Security Score -----------------")
	color := "\033[1;32m" // Green
	if target.RiskScore > 75 {
		color = "\033[1;31m" // Red
	} else if target.RiskScore > 35 {
		color = "\033[1;33m" // Yellow
	}
	fmt.Printf("Risk Factor:     %s%d / 100\033[0m\n", color, target.RiskScore)
	fmt.Printf("Violations Count:%d\n", target.ViolationsCount)
	fmt.Println("==================================================")
}

func handleLogs(daemonURL string) {
	if len(os.Args) < 3 {
		fmt.Println("Error: Sandbox ID is required")
		fmt.Println("Usage: aegis logs <sandbox-id>")
		os.Exit(1)
	}
	targetID := os.Args[2]

	url := fmt.Sprintf("%s/api/logs?sandbox_id=%s", daemonURL, targetID)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error: Failed to connect to secure daemon.")
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Error: Failed to fetch transaction log records.")
		os.Exit(1)
	}

	var logs []AuditRecord
	if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
		fmt.Println("Error: Failed to decode logs.")
		os.Exit(1)
	}

	if len(logs) == 0 {
		fmt.Println("No audit records found for sandbox: " + targetID)
		return
	}

	fmt.Println("\n🛡️  AegisCore Secure Forensic Audit Records Ledger")
	fmt.Println("==========================================================================================================")
	fmt.Printf("%-24s | %-12s | %-12s | %-20s | %s\n", "TIMESTAMP", "TYPE", "LEVEL", "ACTION", "MESSAGE")
	fmt.Println("----------------------------------------------------------------------------------------------------------")

	for _, rec := range logs {
		levelColor := "\033[0m"
		if rec.Level == "CRITICAL" {
			levelColor = "\033[1;31m"
		} else if rec.Level == "WARNING" {
			levelColor = "\033[1;33m"
		}

		timeStr := rec.Timestamp.Format("2006-01-02 15:04:05.000")
		fmt.Printf("%-24s | %-12s | %-19s | %-20s | %s\n", 
			timeStr,
			rec.Type,
			levelColor+rec.Level+"\033[0m",
			rec.Action,
			rec.Message,
		)
	}
	fmt.Println("==========================================================================================================")
}

func handleKill(daemonURL string) {
	if len(os.Args) < 3 {
		fmt.Println("Error: Sandbox ID is required")
		fmt.Println("Usage: aegis kill <sandbox-id>")
		os.Exit(1)
	}
	targetID := os.Args[2]

	url := fmt.Sprintf("%s/api/sandbox/kill?id=%s", daemonURL, targetID)
	resp, err := http.Post(url, "application/json", nil)
	if err != nil {
		fmt.Println("Error: Failed to connect to secure daemon.")
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Error: Terminate command failed (Status %d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	fmt.Printf("\033[1;32m[SUCCESS]\033[0m Sandbox container '%s' was killed successfully. Standard isolation cleanup executed.\n", targetID)
}
