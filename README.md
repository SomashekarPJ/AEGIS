# AegisCore 🛡️

### OS-Level Secure Process Isolation & Sandbox Management Framework

AegisCore is a zero-trust, enterprise-grade process isolation runtime and sandbox orchestration suite designed for Linux-based systems. It enforces fine-grained filesystem restrictions, network ingress/egress boundaries, system call intercepts (seccomp filters), and cgroups v2 resource governance on untrusted workloads.

The framework implements a **dual-mode architecture** to facilitate seamless engineering, auditing, and interactive testing across platforms:
1. **Deterministic Security Simulation Mode**: Automatically boots on non-Linux hosts (such as Windows or macOS) or in unprivileged dev spaces. It mimics kernel namespaces, handles cgroups v2 resource capping and throttling transitions, simulates seccomp-blocked syscall indicators, and broadcasts high-fidelity, real-time threat telemetry via a Server-Sent Events (SSE) stream.
2. **Native Linux Isolation Mode**: Actively mounts real Linux namespaces (`PID`, `MOUNT`, `NET`, `IPC`, `UTS`), drops standard capabilities dynamically, handles direct seccomp-BPF blocks, manipulates cgroups v2 sysfs limits (`cpu.max`, `memory.max`), and executes process containment under root privileges.

---

## Technical Architecture

```
           +---------------------------------------------+
           |           SOC Dashboard (Vite/React)        |
           |             http://localhost:8080/          |
           +----------------------+----------------------+
                                  |
                        WebSockets & SSE Stream
                                  |
                                  v
+---------------+          +------+------+          +-----------------+
|  Aegis CLI    | -------->|  aegisd API | <------- |  Aegis CLI      |
|  (aegis run)  |  REST    |  Orchestrator|  REST   |  (aegis logs)   |
+---------------+          +------+------+          +-----------------+
                                  |
                  +---------------+---------------+
                  |                               |
                  v                               v
       [Target: Linux Kernel]           [Target: Windows/Mac]
  +---------------+---------------+   +---------------+---------------+
  |   Native Linux Sandbox        |   |   Deterministic Simulator     |
  |  - PID, MOUNT, NET Namespaces |   |  - Emulated Syscall Intercept |
  |  - Cgroups v2 Resource Cap    |   |  - Threat Anomaly Generator   |
  |  - Seccomp-BPF Filter Block   |   |  - Cgroups Throttle Modeling  |
  +---------------+---------------+   +---------------+---------------+
                  |                               |
                  +---------------+---------------+
                                  |
                                  v
                    +-------------+-------------+
                    | SQLite Audit Logs Database |
                    |      (audit_logs.jsonl)   |
                    +---------------------------+
```

---

## Component Layout

```
/
├── cmd/
│   ├── aegis/            # Aegis Command-Line Interface (CLI) executable
│   │   └── main.go
│   └── aegisd/           # Secure Execution Daemon (aegisd) orchestrator
│       └── main.go
├── pkg/
│   ├── config/           # YAML security policy compiler & schema parsing
│   ├── daemon/           # HTTP/SSE endpoints and sandbox lifecycle controllers
│   ├── db/               # High-frequency JSON Transaction Ledger database
│   ├── monitoring/       # Cybersecurity threat scoring and active defense mitigations
│   └── sandbox/          # Sandbox abstractions, native Linux engines, and Windows mocks
├── dashboard/            # Vite + React + Canvas Security Operations Center (SOC) UI
├── demo/                 # Test policies and unverified Python payloads
├── Dockerfile            # Multi-stage privileged Go/React Linux build
├── docker-compose.yml    # Docker Compose orchestration configurations
└── README.md             # Systems Engineering Handbook
```

---

## ⚡ Deployment & Running Guide

### Option A: Local Engineering Simulation Mode (Windows/macOS)
Running locally compiles the Go Daemon and serves our compiled SOC dashboard, fallbacks to the high-fidelity security emulator, and streams real-time threat violations.

#### Prerequisites
- Node.js (v18+)
- Go (v1.20+) *[Optional: only if compiling Go natively on the Windows host. If not installed, utilize the Docker option below]*

#### 1. Compile the SOC Dashboard Assets
```bash
cd dashboard
npm install
npm run build
cd ..
```
*This compiles our React + HTML5 Canvas dashboard into `dashboard/dist`.*

#### 2. Run the Secure Daemon (`aegisd`)
If you have Go installed on your host system:
```bash
go run cmd/aegisd/main.go --port 8080
```
If you do not have Go installed natively, run the pre-built Docker container (Option B).

#### 3. Access the SOC Dashboard
Open your browser and navigate to:
👉 **[http://localhost:8080](http://localhost:8080)**

---

### Option B: Native Linux Kernel Mode (Docker Containers)
Runs the entire ecosystem natively inside a privileged container with actual namespace segregation and cgroups v2 resource capping.

#### Prerequisites
- Docker Desktop (or native Linux Docker engine)

#### 1. Build and Launch AegisCore Privileged Node
From the root workspace directory, run:
```bash
docker compose up --build
```
*This builds the multi-stage image (Vite compiler + Go compiler) and starts the secure daemon inside a privileged environment.*

#### 2. Access the SOC Dashboard
Navigate to:
👉 **[http://localhost:8080](http://localhost:8080)**

---

## 💻 CLI Commands & Telemetry Scenarios

AegisCore includes an administrative systems command-line tool `aegis`. 
Ensure `aegisd` is active and running in a background terminal.

### 1. Execute an Untrusted Payload
Instruct AegisCore to launch our demo python workload inside a sandbox managed by our strict declarative security blueprint:
```bash
go run cmd/aegis/main.go run demo/malware.py --policy demo/strict.yaml --name malware-run
```

### 2. Live Inspection
Obtain an infrastructure scorecard for the sandboxed process (CPU/RAM metrics, Host PID, dynamic Risk index, and active violations count):
```bash
go run cmd/aegis/main.go inspect <sandbox-id>
```
*(e.g., `go run cmd/aegis/main.go inspect sb-f2e1a3d5`)*

### 3. Display Audit Records Log
Query the secure log database for forensic traces of kernel blocks:
```bash
go run cmd/aegis/main.go logs <sandbox-id>
```

### 4. Active Containment Kill
Instantly dismantle sandbox boundaries and execute administrative containment:
```bash
go run cmd/aegis/main.go kill <sandbox-id>
```

---

## 🛡️ Declarative Security Policy Specification

Security blueprints are declared in YAML. AegisCore parses, compiles, and applies these rules dynamically:

```yaml
sandbox:
  name: untrusted-python

filesystem:
  read_only:
    - /usr
    - /bin
    - /lib
    - /lib64

  deny:
    - /etc/shadow
    - /etc/sudoers
    - /home
    - /root

network:
  allow:
    - api.github.com
    - login.microsoft.com

resources:
  memory: 256MB
  cpu: 1.0
  disk: 100MB

syscalls:
  deny:
    - ptrace
    - mount
    - reboot
    - kexec_load
    - unshare

execution:
  timeout: 60s
```

### Defense Actions Trigger Matrix
AegisCore evaluates system calls and memory allocations in real-time, calculating a dynamic **Risk Rating** index:
- **Risk Score >= 50**: Injects dynamic **cgroup throttling**. Reduces CPU share to 5.0% and constrains RAM ceilings (visible as yellow alerts in the visualizer).
- **Risk Score >= 80**: Triggers **Active Threat Quarantine**. Broadcasts red alerts, locks down socket paths, freezes guest processes via a SIGSTOP kernel signal, and isolates the workload completely.
