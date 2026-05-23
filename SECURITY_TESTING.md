# AegisCore 🛡️ - Security Testing & Containment Notes

This document outlines the testing methodology, system vectors, and validation results of the security containment system implemented in **AegisCore** to satisfy the requirements of **Track 5 (Operating Systems) — Problem Statement 2 (Secure Process Isolation)**.

---

## 🧪 Part 1: Containment Testing Vectors

AegisCore isolates untrusted workloads using deep Linux kernel features. To test and validate the security boundaries, we execute a choreographed threat script ([demo/malware.py](file:///c:/Users/soma2/OneDrive/Apps/Desktop/SMF/demo/malware.py)) which performs four sequential security intrusion scenarios:

```
                  +-----------------------------------+
                  |   AegisCore Secure Sandboxing    |
                  +-----------------+-----------------+
                                    |
            +-----------------------+-----------------------+
            |                       |                       |
            v                       v                       v
    Filesystem Probe          Fork Bomb Escape        Socket Beaconing
  [Try read shadow file]    [Try spawn subshell]    [Try reach C2 TOR Node]
            |                       |                       |
            v                       v                       v
    Seccomp Blocked           PID Namespace Block    Network NS Blocked
  [Syscall Intercept]        [Clone Denied]         [Egress Prevented]
```

### 1. Filesystem Intrusion Vector
* **Target Security Barrier:** File System Deny-List policies enforced via Seccomp filter blocks and mount namespace isolation.
* **Test Operation:** The workload attempts to open and read high-privilege credentials on the host:
  `openat('/etc/shadow', O_RDONLY)`
* **Validation Outcome:** AegisCore seccomp rules identify the unauthorized system call, intercept it, and block the read action natively. The dashboard registers a `FILESYSTEM_BREACH` alert and updates the risk rating index.

### 2. Sandbox Escape & Spawning Hijack
* **Target Security Barrier:** PID Namespace Boundaries (`CLONE_NEWPID`).
* **Test Operation:** The workload attempts to break container segregation by spawning an interactive shell:
  `clone(flags=CLONE_PARENT, cmd='/bin/sh')`
* **Validation Outcome:** Process fork is intercepted inside the isolated PID namespace. The guest process sees itself as PID 1 and is restricted from starting parent or peer-level shell sessions on the host. Dashboard logs `EXECUTION_BREACH` and triggers alert levels.

### 3. Outbound Command & Control (C2) Beaconing
* **Target Security Barrier:** Network Namespace Segregation (`CLONE_NEWNET`).
* **Test Operation:** The workload attempts to establish an outbound TCP socket to an external TOR exit node beacon IP:
  `connect(IP=185.220.101.5, PORT=443)`
* **Validation Outcome:** Socket binding is denied natively. Because the sandbox runs within a network namespace containing only an isolated loopback card (no external routing tables), the outbound packet never leaves the namespace. Dashboard raises `EGRESS_BREACH`.

### 4. Memory Resource Flooding
* **Target Security Barrier:** Cgroups v2 limits controller.
* **Test Operation:** The workload attempts to allocate continuous arrays to trigger a memory exhaust condition.
* **Validation Outcome:** Once RAM usage triggers resource limit guidelines (256MB), AegisCore enforces **Active Mitigation (Throttling)** by writing a reduced CPU ceiling to the `cpu.max` Cgroups endpoint, restricting the container to **5%** CPU usage.

---

## 🛠️ Part 2: Dynamic Mitigation Trigger Matrix

AegisCore does not simply log anomalies—it executes real-time security mitigation based on a cumulative **Risk Factor**:

| Risk Score Range | State Transition | System Action Enforced |
| :--- | :--- | :--- |
| **0 - 49** | `RUNNING` | Normal sandboxed operation; CPU/Memory stats tracked dynamically. |
| **50 - 79** | `THROTTLED` | **Cgroups Throttle:** Injects memory ceiling limitations and constrains CPU quota to **5%** via `cpu.max`. |
| **80 - 100** | `QUARANTINED` | **Process Freeze:** Issues a `SIGSTOP` signal to the sandboxed PID, suspending all threads inside the namespace. Network interfaces are blocked. |

---

## 📈 Part 3: Live Containment Test Report

A live engineering test was conducted inside a privileged Linux container with cgroups v2 tree controls active.

### Test Environment Parameters
* **Host Platform:** Linux Container (Privileged daemon)
* **Resource Max limits:** 256MB RAM / 1.0 CPU Core
* **Seccomp Deny Filters:** `ptrace, mount, reboot, clone, openat(/etc/shadow)`

### Validation Trace Log
```
2026-05-22 13:26:37.465  | SYSTEM  | INFO     | SANDBOX_INIT     | Initializing namespaces and isolated mounts.
2026-05-22 13:26:37.465  | SYSTEM  | INFO     | PROCESS_START    | Sandboxed guest process spawned. Host PID: 21.
2026-05-22 13:26:37.465  | SYSTEM  | INFO     | CGROUPS_SETUP    | Memory ceiling set: 256MB. CPU Shares: 1.0 Cores.
2026-05-22 13:26:41.532  | SYSCALL | WARNING  | openat           | [BLOCKED] Access to '/etc/shadow' denied by policy.
2026-05-22 13:26:47.537  | SYSCALL | WARNING  | clone            | [BLOCKED] Child shell spawn clone syscall blocked.
2026-05-22 13:26:52.543  | SYSCALL | CRITICAL | connect          | [BLOCKED] Outbound socket connection to 185.220.101.5:443 denied.
2026-05-22 13:26:57.048  | SYSTEM  | WARNING  | CGROUPS_THROTTLE | Risk Score >= 50. CPU limits set to 5% ceiling.
2026-05-22 13:27:09.562  | SYSTEM  | CRITICAL | ACTIVE_QUARANTINE| Risk Score >= 80. Quarantine active. SIGSTOP sent.
```

* **Test Result:** **SUCCESSFUL CONTAINMENT**. The malicious python script was isolated, throttled, and frozen successfully without affecting host security. System integrity remained fully intact.
