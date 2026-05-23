package daemon

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"aegiscore/pkg/config"
	"aegiscore/pkg/db"
	"aegiscore/pkg/monitoring"
	"aegiscore/pkg/sandbox"

	"github.com/google/uuid"
)

// DaemonServer orchestrates sandbox nodes and feeds frontend consoles
type DaemonServer struct {
	sandboxes map[string]sandbox.Sandbox
	eventChan chan interface{}
	threatEng *monitoring.ThreatEngine
	auditDB   *db.AuditDB
	clients   map[chan interface{}]bool
	mu        sync.RWMutex
}

// NewDaemonServer starts core orchestrator resources
func NewDaemonServer(auditLogPath string) (*DaemonServer, error) {
	// Construct logging folder if needed
	_ = os.MkdirAll(filepath.Dir(auditLogPath), 0755)

	auditDB, err := db.OpenAuditDB(auditLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit db: %w", err)
	}

	srv := &DaemonServer{
		sandboxes: make(map[string]sandbox.Sandbox),
		eventChan: make(chan interface{}, 1000),
		threatEng: monitoring.NewThreatEngine(),
		auditDB:   auditDB,
		clients:   make(map[chan interface{}]bool),
	}

	// Spin up central broker thread
	go srv.eventBrokerLoop()

	return srv, nil
}

// StartSandbox spawns a secure container
func (s *DaemonServer) StartSandbox(name string, workloadPath string, policyPath string) (sandbox.Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sandboxID := fmt.Sprintf("sb-%s", uuid.New().String()[:8])

	// Load declarative policy
	var policy *config.Policy
	var err error
	if policyPath != "" {
		policy, err = config.LoadPolicy(policyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load policy: %w", err)
		}
	} else {
		policy = config.DefaultPolicy()
	}

	// Set name
	policy.Sandbox.Name = name

	// Register behavioral tracker
	s.threatEng.RegisterSandbox(sandboxID, policy)

	// Create dynamic sandbox (with target compilation OS selection)
	var sb sandbox.Sandbox

	// Utilizes dual-compilation abstraction
	sb = createTargetSandbox(sandboxID, name, workloadPath, policy, s.eventChan)

	s.sandboxes[sandboxID] = sb

	// Trigger Start
	if err := sb.Start(); err != nil {
		s.threatEng.DeregisterSandbox(sandboxID)
		delete(s.sandboxes, sandboxID)
		return nil, err
	}

	return sb, nil
}

// KillSandbox terminates container boundaries
func (s *DaemonServer) KillSandbox(id string) error {
	s.mu.RLock()
	sb, exists := s.sandboxes[id]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("sandbox node %s not found", id)
	}

	return sb.Kill()
}

// QuarantineSandbox manual trigger
func (s *DaemonServer) QuarantineSandbox(id string) error {
	s.mu.RLock()
	sb, exists := s.sandboxes[id]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("sandbox node %s not found", id)
	}

	return sb.Quarantine()
}

// Broadcast central broker
func (s *DaemonServer) eventBrokerLoop() {
	for rawEvt := range s.eventChan {
		s.mu.Lock()
		// Save events to persistent audit ledger
		if evt, ok := rawEvt.(sandbox.Event); ok {
			_, _ = s.auditDB.WriteRecord(
				evt.SandboxID,
				evt.Type,
				evt.Level,
				evt.Category,
				evt.Action,
				evt.Message,
			)

			// Update threat metrics dynamic state
			if evt.Type == "ALERT" {
				// Re-verify quarantine states
			}
		}

		// Broadcast JSON to active websocket dashboard clients
		for clientChan := range s.clients {
			select {
			case clientChan <- rawEvt:
			default:
				// Dropping slow client
				close(clientChan)
				delete(s.clients, clientChan)
			}
		}
		s.mu.Unlock()
	}
}

// REST Handlers
func (s *DaemonServer) SetupRoutes() http.Handler {
	mux := http.NewServeMux()

	// CORS Preflight setup for development dashboards
	corsMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next(w, r)
		}
	}

	mux.HandleFunc("/api/sandbox/run", corsMiddleware(s.handleRun))
	mux.HandleFunc("/api/sandboxes", corsMiddleware(s.handleList))
	mux.HandleFunc("/api/sandbox/kill", corsMiddleware(s.handleKill))
	mux.HandleFunc("/api/sandbox/quarantine", corsMiddleware(s.handleQuarantine))
	mux.HandleFunc("/api/sandbox/clear", corsMiddleware(s.handleClearHistory))
	mux.HandleFunc("/api/logs", corsMiddleware(s.handleLogs))
	mux.HandleFunc("/api/workload/scan", corsMiddleware(s.handleWorkloadScan))
	mux.HandleFunc("/api/events", s.handleEventsWS) // WebSocket

	// Serve static compiled frontend dashboard if present in assets folder
	distPath := "./dist"
	if _, err := os.Stat(distPath); err == nil {
		mux.Handle("/", http.FileServer(http.Dir(distPath)))
	} else {
		distPath = "./dashboard/dist"
		if _, err = os.Stat(distPath); err == nil {
			mux.Handle("/", http.FileServer(http.Dir(distPath)))
		}
	}

	return mux
}

type RunRequest struct {
	Name         string `json:"name"`
	WorkloadPath string `json:"workload_path"`
	PolicyPath   string `json:"policy_path"`
	CodeContent  string `json:"code_content"`
}

type ScanRequest struct {
	FileName    string `json:"file_name"`
	CodeContent string `json:"code_content"`
}

func decodeUploadedContent(codeContent string) ([]byte, error) {
	if strings.HasPrefix(codeContent, "data:") && strings.Contains(codeContent, ";base64,") {
		parts := strings.SplitN(codeContent, ";base64,", 2)
		if len(parts) != 2 {
			return []byte(codeContent), nil
		}
		fileData, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 file payload: %w", err)
		}
		return fileData, nil
	}
	return []byte(codeContent), nil
}

func safeWorkloadName(name string) string {
	if name == "" {
		return "custom_uploaded_payload"
	}
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "..", "")
	return name
}

func (s *DaemonServer) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Write custom code contents if provided
	if req.CodeContent != "" {
		safeName := safeWorkloadName(req.Name)

		workloadDir := "./demo"
		_ = os.MkdirAll(workloadDir, 0755)

		fileData, err := decodeUploadedContent(req.CodeContent)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ext := ".py"
		if req.WorkloadPath != "" {
			workloadExt := filepath.Ext(strings.ToLower(req.WorkloadPath))
			if workloadExt == ".py" || workloadExt == ".sh" || workloadExt == ".pdf" {
				ext = workloadExt
			}
		} else {
			lowerName := strings.ToLower(safeName)
			if strings.HasSuffix(lowerName, ".py") || strings.HasSuffix(lowerName, ".sh") || strings.HasSuffix(lowerName, ".pdf") {
				ext = ""
			}
		}
		if strings.HasSuffix(strings.ToLower(safeName), ext) {
			ext = ""
		}

		filePath := filepath.Join(workloadDir, safeName+ext)
		err = os.WriteFile(filePath, fileData, 0644)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to write custom script file: %v", err), http.StatusInternalServerError)
			return
		}
		req.WorkloadPath = filePath
	}

	if req.WorkloadPath == "" {
		http.Error(w, "workload_path or code_content is required", http.StatusBadRequest)
		return
	}

	sb, err := s.StartSandbox(req.Name, req.WorkloadPath, req.PolicyPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to spawn sandbox: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sb.Info())
}

func (s *DaemonServer) handleWorkloadScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.CodeContent == "" {
		http.Error(w, "code_content is required", http.StatusBadRequest)
		return
	}

	fileData, err := decodeUploadedContent(req.CodeContent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sandbox.AnalyzeWorkloadBytes(req.FileName, fileData))
}

func (s *DaemonServer) handleList(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	infos := make([]*sandbox.SandboxInfo, 0, len(s.sandboxes))
	for _, sb := range s.sandboxes {
		infos = append(infos, sb.Info())
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(infos)
}

func (s *DaemonServer) handleKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}

	if err := s.KillSandbox(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"success"}`))
}

func (s *DaemonServer) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}

	if err := s.QuarantineSandbox(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"success"}`))
}

func (s *DaemonServer) handleClearHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for id, sb := range s.sandboxes {
		status := sb.Status()
		if status == sandbox.StateTerminated || status == sandbox.StateFailed {
			s.threatEng.DeregisterSandbox(id)
			delete(s.sandboxes, id)
		}
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"success"}`))
}


func (s *DaemonServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	sandboxID := r.URL.Query().Get("sandbox_id")
	minLevel := r.URL.Query().Get("level")

	records := s.auditDB.QueryRecords(sandboxID, minLevel)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(records)
}

// handleEventsWS processes simple WebSocket streams or fallbacks to SSE (Server-Sent Events)
// To guarantee zero external dependencies (no third-party gorilla/websocket requirement)
// we implement Server-Sent Events (SSE), which is natively supported by Javascript's EventSource
// and is incredibly robust, fast, and does not require building compiled binary socket headers!
func (s *DaemonServer) handleEventsWS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	clientChan := make(chan interface{}, 100)

	s.mu.Lock()
	s.clients[clientChan] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if _, exists := s.clients[clientChan]; exists {
			delete(s.clients, clientChan)
			close(clientChan)
		}
		s.mu.Unlock()
	}()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Keep alive ticker
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			// Ping connection
			_, _ = fmt.Fprintf(w, "event: ping\ndata: {}\n\n")
			flusher.Flush()
		case evt, open := <-clientChan:
			if !open {
				return
			}
			jsonData, err := json.Marshal(evt)
			if err == nil {
				_, _ = fmt.Fprintf(w, "data: %s\n\n", string(jsonData))
				flusher.Flush()
			}
		}
	}
}
