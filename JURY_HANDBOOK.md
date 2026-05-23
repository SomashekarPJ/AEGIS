# AegisCore 🛡️ - Systems Engineering Jury Handbook & Pitch-Deck

Welcome to the **AegisCore Jury Handbook**. This document serves as a complete technical guide, live demonstration script, and Q&A playbook to help you present this framework to the hackathon evaluation jury.

---

## 🚀 Part 1: Live Demonstration Running Steps

To show the jury a high-fidelity, zero-friction demonstration, follow these exact setup and execution steps.

### **Option A: Containerized Native Linux Isolation (Recommended)**
Use this to demonstrate **real operating-system kernel-level sandboxing** (Namespaces, Cgroups v2, and Seccomp).

#### **1. Spin up the AegisCore Node**
From the repository root directory, boot the daemon and compiled dashboard inside a privileged container:
```bash
docker compose up --build -d
```
*This mounts the host cgroup tree (`/sys/fs/cgroup`) in read-write mode and exposes the dashboard at port 8080.*

#### **2. Load the SOC Dashboard**
Open your browser and navigate to:
👉 **[http://localhost:8080](http://localhost:8080)**

#### **3. Execute the Malware Simulation live**
Open a separate terminal window and instruct AegisCore to launch the unverified python script:
```bash
docker exec -it aegis_core_daemon aegis run demo/malware.py --policy demo/strict.yaml
```

#### **4. Watch the Real-Time Containment Lifecycle**
As the payload runs, point the jury to the dashboard:
* **Boot Phase:** The dashboard shows `malware-sandbox` starting as **Green (RUNNING)**.
* **Intrusion Blocks:** Watch the console log real-time blocks for Shadow file access, shell spawning (`clone`), and TCP socket beaconing.
* **Resource Capping:** The script hits the hard memory ceiling. AegisCore intercepts the breach and transitions the sandbox to **Orange (THROTTLED)**, writing dynamic CPU ceilings directly to the Cgroups controller.
* **Total Freeze:** The risk score hits `95/100`. AegisCore issues a kernel-level `SIGSTOP` signal, moving the sandbox to a **Flashing Red (QUARANTINED)** state, freezing the process instantly.

---

### **Option B: Local Simulation Mode (Windows/macOS Fallback)**
Use this option if you are running on a machine without Docker or direct Linux kernel access.

#### **1. Compile Dashboard Assets**
```bash
cd dashboard
npm install
npm run build
cd ..
```

#### **2. Launch the Go Daemon**
```bash
go run cmd/aegisd/main.go --port 8080
```
*AegisCore automatically detects the host OS (Windows/Mac) and boots the high-fidelity security emulator.*

#### **3. Access the SOC Dashboard**
👉 **[http://localhost:8080](http://localhost:8080)**
*Click the **"+" (Workload Registry)** button on the top-left to spawn virtual sandboxes, and watch the high-fidelity simulation sequence execute live on the screen!*

---

## 🎨 Part 2: Premium Visual Features on the SOC Dashboard

Explain these dynamic web-dashboard features to show the jury the level of craft in your implementation:

```
    [PENDING] (Cyan)        ==> Sandboxing environment initializing
        │
        ▼
     [RUNNING] (Green)       ==> Namespaces active, live telemetry streaming
        │
        ▼
    [THROTTLED] (Orange)     ==> Cgroup hard-throttles memory & CPU to 5%
        │
        ▼
   [QUARANTINED] (Red)       ==> Process suspended (SIGSTOP), network locked
```

### **1. Real-Time HTML5 Canvas Topology Map**
* *The Visualizer:* The dashboard draws a dynamic, glowing topology ring linking the sandbox to its active operating system controllers: **Filesystem, Process Control, Egress Network, Seccomp Syscalls, and Cgroup Quotas**.
* *Live Color Shifting:*
  * **Cyan (PENDING):** Visualizes sandbox environment compilation.
  * **Green (RUNNING):** Shows a healthy, isolated process loop with dynamic green pulses.
  * **Orange (THROTTLED):** Intercept circles glow orange, showing resource constraints in progress.
  * **Flashing Red (QUARANTINED):** The topology ring shifts to a severe red alert state, indicating the guest process is frozen in the kernel.

### **2. eBPF Syscall Trace Console**
* Provides a real-time, scrolling systems telemetry console at the bottom-right.
* Shows exact kernel system calls being trapped and blocked (`openat`, `clone`, `connect`, `sleep`) with millisecond timestamps and security categorizations.

### **3. Telemetry & Risk Gauges**
* **Live Memory Utilization:** Polled directly from Cgroups (`memory.current` in Linux).
* **Dynamic Risk Index Scorecard:** A real-time dial (0 to 100) calculating the cumulative threat severity of the workload on the fly.
* **Compliance Counter:** Accumulates total security policy violations as they happen.

---

## 🏆 Part 3: Deep Technical Architecture (For the Experts)

Explain these structural abstractions to prove that AegisCore is a real systems product:

### **1. The Dual-Compilation Strategy (Go Interfaces)**
AegisCore abstracts process control through a clean Go `Sandbox` interface:
```go
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
```
* On Linux hosts, the compiler loads `runtime_linux.go`, utilizing actual `syscall.CLONE` namespaces and cgroups directory operations under root permission.
* On non-Linux hosts, the compiler loads `runtime_mock.go`, launching a high-fidelity threat and metrics simulator.

### **2. Active Mitigation & Cgroup filesystem adjustments**
When risk scores exceed the warning threshold, the daemon alters execution boundaries on the fly:
* **Throttling:** Rewrites the cgroups v2 resource configuration at `/sys/fs/cgroup/aegis/<sandbox-id>/cpu.max` to `5000 100000` (capping CPU to 5% cores) and limits virtual memory limits to `32MB`.
* **Quarantining:** Issues a `syscall.SIGSTOP` signal directly to the guest PID, suspending all threads inside the namespace. Network isolation is achieved natively via `CLONE_NEWNET` having only loopback access.

---

## 🙋‍♂️ Part 4: Jury Q&A Playbook (Win the Room)

#### **Q1: Why use Go for the backend instead of Python or Node.js?**
> *"Low-level systems engineering demands high concurrency, native access to kernel system headers, and zero garbage collection latency. Go compiles to a single, static binary with no external dependencies, allowing us to interact directly with Linux system calls and directories while maintaining a tiny resource footprint."*

#### **Q2: What is the benefit of your Server-Sent Events (SSE) stream over traditional WebSockets?**
> *"WebSockets require third-party libraries (like Gorilla) and add significant network protocol overhead for bi-directional communication. Since our dashboard is read-only (telemetry flows from the daemon *to* the browser), Server-Sent Events (SSE) is the perfect engineering choice. SSE uses standard, lightweight HTTP streaming natively supported by browsers via `EventSource`, requires zero external dependencies, and easily passes through enterprise firewalls."*

#### **Q3: How secure is this sandboxing method compared to standard Docker?**
> *"Docker is optimized for app deployment, not security. A compromised Docker process running as root can escape to the host. AegisCore implements deeper hardening: we drop administrative kernel capabilities dynamically (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`), force sandboxes to run inside unprivileged user namespaces, inject strict Seccomp filters to block dangerous syscalls, and implement active resource throttling inside Cgroups v2 on the fly."*

#### **Q4: How does AegisCore monitor anomalies without using heavy eBPF kernel modules?**
> *"While eBPF requires privileged kernel compile headers (making deployment heavy), AegisCore uses a lightweight **Dual-Telemetry approach**. We read exact RAM metrics natively from the Cgroups filesystem (`memory.current`) and run a high-performance **Stdout/Stderr pipe parser** that converts structured workload security logging into real-time socket events instantly. This provides a production-grade, zero-dependency detection system."*
