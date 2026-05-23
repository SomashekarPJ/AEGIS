# AegisCore 🛡️ - OS-Level Process Isolation & Sandbox Orchestration
### ZYNEX Hackathon Software Pitch-Deck (Track 5: Operating Systems — Problem Statement 2)

AegisCore is a zero-trust, enterprise-grade process isolation runtime and sandbox orchestration suite. It enforces fine-grained filesystem restrictions, network ingress/egress boundaries, system call intercepts (seccomp filters), and cgroups v2 resource governance on untrusted workloads.

---

## 💎 The Engineering Problem & Solution Space

> [!IMPORTANT]
> **Track 5, Problem Statement 2 (Secure Process Isolation)**
> *   **The Threat:** Modern systems execute unverified third-party scripts and plugins. A single compromised process can probe host directories, execute subprocesses (`clone`), establish command-and-control (`connect`) sockets, and flood system memory.
> *   **The Shield (AegisCore):** A low-level security framework that contains workloads inside independent kernel boundaries, scorecards anomalies in real-time, and triggers automated hardware containment ceilings on the fly.

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
```

---

## 📂 Core Component Layout & File Map

Here is the exact structure of the AegisCore codebase, mapped by responsibility:

```
/
├── cmd/
│   ├── aegisd/                  # [DAEMON] Secure HTTP API, SSE Broker & Orchestrator
│   │   └── main.go
│   └── aegis/                   # [CLI] Systems Admin command-line tool (run, inspect, logs)
│       └── main.go
├── pkg/
│   ├── config/                  # [POLICY] YAML Declarative Schema Compiler
│   │   └── policy.go
│   ├── daemon/                  # [API] Route Handlers, SSE Keep-Alive & Client Feeds
│   │   └── server.go
│   ├── db/                      # [LEDGER] High-Performance JSON Transaction Database
│   │   └── sqlite.go
│   ├── monitoring/              # [THREAT] Dynamic Anomaly Scoring Engine
│   │   └── threat.go
│   └── sandbox/                 # [CONTAINMENT] Dual-mode sandboxing interfaces
│       ├── types.go             # Common structures and lifecycle states
│       ├── runtime_mock.go      # High-fidelity Windows/macOS deterministic simulator
│       └── runtime_linux.go     # Native kernel namespaces, Cgroups v2 & Seccomp
├── dashboard/                   # [SOC CONSOLE] Vite + React + HTML5 Canvas Dashboard
│   ├── src/App.tsx              # Interactive visual topology grid & telemetry dials
│   └── src/index.css            # Custom cyber-dark stylesheet tokens & glow keyframes
├── demo/                        # [WORKLOADS] Sandbox test profiles & unverified python binaries
│   ├── strict.yaml              # Strict zero-trust security configuration blueprint
│   └── malware.py               # Choreographed intrusion payload script
├── Dockerfile                   # Multi-stage Docker builder (React build + Alpine binary compile)
└── docker-compose.yml           # Privileged Linux container orchestration profile
```

---

## ⚡ Active Defense Threat Mitigation Matrix

AegisCore calculates a cumulative **Risk Index Score (0-100)** on the fly, transforming process containment instantly as threat levels escalate:

| Risk Rating | Containment State | Host Kernel Defense Enforced | SOC Color Indicator |
| :---: | :---: | :--- | :---: |
| **0 - 49** | `RUNNING` | Standard isolated loop; namespaces active; telemetry streaming. | **Green Pulse** |
| **50 - 79** | `THROTTLED` | **Cgroups Throttling:** CPU quota capped to **5.0%** core share via `cpu.max` and Memory ceiling set to `32MB` via `memory.max`. | **Yellow Glow** |
| **80 - 100** | `QUARANTINED` | **Process Freeze:** Issues a `syscall.SIGSTOP` signal to suspend all threads inside the namespace. Network socket pathways locked down. | **Flashing Red** |

---

## 🧬 Live Intrusion Mitigation Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Workload as Sandboxed Workload (malware.py)
    participant Kernel as Linux Kernel (namespaces/cgroups/seccomp)
    participant Monitor as AegisCore Threat Engine
    participant Mitigator as Cgroups/Sysfs Controller
    participant SOC as React SOC Dashboard (SSE link)

    Workload->>Kernel: Attempts file bypass: openat("/etc/shadow")
    Kernel->>Monitor: Intercept syscall block event
    Monitor->>Monitor: Risk Score += 25
    Monitor->>SOC: Broadcast Alert: UNAUTHORIZED_FILE_ACCESS
    SOC->>SOC: Canvas flashes Satellite "Filesystem" RED!

    Workload->>Kernel: Attempts spawn: clone("/bin/sh")
    Kernel->>Monitor: Intercept clone block
    Monitor->>Monitor: Risk Score += 30 (Risk = 55)
    Monitor->>SOC: Broadcast Alert: PROCESS_HIJACK_ATTEMPT
    
    Note over Monitor, Mitigator: Threat Score >= 50: Trigger Cgroup Mitigation!
    Monitor->>Mitigator: Apply Cgroup limits (CPU -> 5.0%)
    Mitigator->>Kernel: Adjust cpu.max sysfs entry
    Monitor->>SOC: Broadcast state: THROTTLED
    SOC->>SOC: Telemetry Dial drops CPU speed; Central node glowing orange

    Workload->>Kernel: Connects socket to unapproved Tor node
    Kernel->>Monitor: Intercept connection block
    Monitor->>Monitor: Risk Score += 35 (Risk = 90)
    Monitor->>SOC: Broadcast Alert: NETWORK_BEACONING_DETECTION
    
    Note over Monitor, Mitigator: Threat Score >= 80: Trigger Active Quarantine!
    Monitor->>Kernel: Freeze process: SIGSTOP
    Monitor->>SOC: Broadcast state: QUARANTINED
    SOC->>SOC: Central node glowing red and pulsating
```

---

## 🏆 Key Engineering Achievements (Present to the Jury)

1.  **Dual-Mode Compilation Tagging:** Clean Go interface boundaries. The backend compiles natively on Windows/Mac utilizing simulator logic and switches seamlessly to Linux system descriptors inside containers.
2.  **Zero-Dependency SSE Telemetry Stream:** Eschewed heavy external protocols or WebSockets wrappers. Native Server-Sent Events (SSE) stream provides ultra-low latency, read-only kernel metrics feed natively into the browser.
3.  **High-Fidelity HTML5 Canvas Dashboard:** A beautifully animated topology map drawing connections to Namespace, Seccomp, and Cgroups controllers with custom visual color glows and micro-animation rendering.
4.  **CGO-Free Transaction Ledger:** Cross-platform thread-safe transaction database implemented natively in pure Go without locking external platform database dependencies.
