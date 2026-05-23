import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, Cpu, HardDrive, AlertTriangle, 
  Trash2, Play, Activity, Plus, X, CheckCircle, 
  Lock, AlertOctagon, Zap, Upload, FileCode,
  Sun, Moon, Eye, Clock
} from 'lucide-react';

interface Policy {
  sandbox: { name: string };
  filesystem: { read_only: string[]; deny: string[] };
  network: { allow: string[] };
  resources: { memory: string; cpu: number; disk: string };
  syscalls: { deny: string[] };
  execution: { timeout: string };
}

interface SandboxInfo {
  id: string;
  name: string;
  pid: number;
  status: string; // PENDING, RUNNING, THROTTLED, QUARANTINED, TERMINATED, FAILED
  policy: Policy;
  workload_path: string;
  start_time: string;
  duration: string;
  cpu_usage: number;
  memory_usage: number;
  disk_usage: number;
  risk_score: number;
  violations_count: number;
}

interface EventLog {
  timestamp: string;
  sandbox_id: string;
  type: string; // SYSCALL, ALERT, SYSTEM
  level: string; // INFO, WARNING, CRITICAL
  category: string;
  action: string;
  message: string;
}

interface ThreatScanResult {
  malicious: boolean;
  score: number;
  verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  reasons: string[];
}

const DEPLOYED_DAEMON_API = import.meta.env.VITE_DAEMON_API?.replace(/\/$/, '');

const DAEMON_API = DEPLOYED_DAEMON_API || (window.location.origin === 'http://localhost:5173' || window.location.origin === 'http://127.0.0.1:5173' 
  ? 'http://localhost:8080' 
  : window.location.origin);

const STRICT_YAML = `sandbox:
  name: "aegiscore-strict-security-sandbox"
  profile: "strict"

filesystem:
  read_only:
    - "/bin"
    - "/usr/bin"
    - "/lib"
    - "/sbin"
  deny:
    - "/etc/shadow"
    - "/etc/passwd"
    - "/var/run/secrets"

network:
  allow:
    - "127.0.0.1:8080"
    - "api.github.com"

resources:
  memory: "256MB"
  cpu: 1.0
  disk: "500MB"

syscalls:
  deny:
    - "clone"
    - "execve"
    - "ptrace"
    - "socket"
    - "connect"

execution:
  timeout: "60s"`;

const LOW_LATENCY_YAML = `sandbox:
  name: "aegiscore-low-latency-observability-sandbox"
  profile: "low-latency"

filesystem:
  read_only:
    - "/bin"
  deny:
    - "/etc/shadow"

network:
  allow:
    - "*"

resources:
  memory: "512MB"
  cpu: 2.0
  disk: "1000MB"

syscalls:
  deny:
    - "ptrace"

execution:
  timeout: "180s"`;

const localThreatScan = (fileName: string, content: string): ThreatScanResult => {
  const lowerName = fileName.toLowerCase();
  const lowerContent = content.toLowerCase();
  let score = 0;
  const reasons: string[] = [];
  const addSignal = (points: number, reason: string) => {
    score += points;
    reasons.push(reason);
  };
  const hasAny = (...needles: string[]) => needles.some(needle => lowerContent.includes(needle));

  if (['malware', 'exploit', 'phishing', 'infected'].some(term => lowerName.includes(term))) {
    addSignal(20, 'suspicious filename');
  }
  if (hasAny('breach_attempt', 'seccomp_block', 'kernel_contain', 'network_lockdown', 'quarantine_lock')) {
    addSignal(35, 'explicit sandbox breach or containment markers');
  }
  if (hasAny('privilege escalation', 'credential', 'keylogger', 'ransomware', 'trojan', 'reverse shell', 'meterpreter')) {
    addSignal(25, 'malware behavior keywords');
  }
  if (hasAny('eicar-standard-antivirus-test-file', 'x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar')) {
    addSignal(50, 'EICAR test malware signature');
  }
  if (hasAny('/etc/shadow', '/etc/passwd', 'sam\\', 'ntds.dit')) {
    addSignal(30, 'credential or protected-file access');
  }
  if (hasAny('socket(', 'connect(', 'urllib.request', 'requests.post', 'curl ', 'wget ', 'http://', 'https://')) {
    addSignal(20, 'outbound network or download behavior');
  }
  if (hasAny('subprocess.', 'os.system', 'popen(', '/bin/sh', 'bash -c', 'powershell', 'cmd.exe', 'wscript.shell')) {
    addSignal(25, 'shell or subprocess execution');
  }
  if (hasAny('base64.b64decode', 'fromcharcode', 'eval(', 'exec(', 'shellcode', 'payload')) {
    addSignal(20, 'obfuscation or dynamic code execution');
  }
  if (hasAny('185.220.101.5', 'tor node', 'c2', 'beacon')) {
    addSignal(30, 'known C2 or beaconing indicator');
  }

  return {
    malicious: score >= 35,
    score,
    verdict: score >= 35 ? 'MALICIOUS' : score > 0 ? 'SUSPICIOUS' : 'CLEAN',
    reasons
  };
};

interface Particle {
  x: number;
  y: number;
  targetX: number;
  targetY: number;
  progress: number;
  speed: number;
  color: string;
  size: number;
}

const getStatusColor = (status: string, riskScore: number): string => {
  if (status === 'TERMINATED' || status === 'FAILED') return 'var(--text-muted)';
  if (status === 'QUARANTINED' || riskScore > 75) return 'var(--accent-red)';
  if (status === 'THROTTLED' || riskScore > 35) return 'var(--accent-yellow)';
  if (riskScore === 0 || status === 'RUNNING') return 'var(--accent-green)';
  return 'var(--accent-cyan)';
};

export default function App() {
  const [sandboxes, setSandboxes] = useState<SandboxInfo[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [logs, setLogs] = useState<EventLog[]>([]);
  const [alerts, setAlerts] = useState<EventLog[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [showRunModal, setShowRunModal] = useState(false);
  const [selectedPolicyTab, setSelectedPolicyTab] = useState('strict.yaml');

  const [isLightTheme, setIsLightTheme] = useState(() => {
    return document.body.classList.contains('light-theme');
  });

  const toggleTheme = () => {
    setIsLightTheme(prev => {
      const next = !prev;
      if (next) {
        document.body.classList.add('light-theme');
      } else {
        document.body.classList.remove('light-theme');
      }
      return next;
    });
  };

  // Form state
  const [runName, setRunName] = useState('malware-sandbox');
  const [runWorkload, setRunWorkload] = useState('demo/malware.py');
  const [runPolicy, setRunPolicy] = useState('demo/strict.yaml');
  const [runCodeContent, setRunCodeContent] = useState('');
  const [useCustomCode, setUseCustomCode] = useState(false);
  const [uploadedFileName, setUploadedFileName] = useState('');
  const [scanResult, setScanResult] = useState<ThreatScanResult | null>(null);
  const [scanError, setScanError] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [runError, setRunError] = useState('');
  const [isRunningWorkload, setIsRunningWorkload] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const particlesRef = useRef<Particle[]>([]);
  const nodeAlertsRef = useRef<{ [key: string]: boolean }>({});

  const selectedSandbox = sandboxes.find(sb => sb.id === selectedId);

  const openFilePicker = () => {
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
      fileInputRef.current.click();
    }
  };

  // Fetch initial sandbox list
  const fetchSandboxes = async () => {
    try {
      const resp = await fetch(`${DAEMON_API}/api/sandboxes`);
      if (resp.ok) {
        const data = await resp.json();
        setSandboxes(data);
        if (data.length > 0 && !selectedId) {
          setSelectedId(data[0].id);
        }
      }
    } catch (e) {
      console.error('Failed to query sandboxes:', e);
    }
  };

  useEffect(() => {
    fetchSandboxes();
    const interval = setInterval(fetchSandboxes, 2000);
    return () => clearInterval(interval);
  }, [selectedId]);

  // Connect to Real-time event SSE server
  useEffect(() => {
    let eventSource: EventSource;

    const connectSSE = () => {
      console.log('Linking telemetric feed...');
      eventSource = new EventSource(`${DAEMON_API}/api/events`);

      eventSource.onopen = () => {
        setIsConnected(true);
        console.log('AegisCore central feed linked successfully.');
      };

      eventSource.onerror = () => {
        setIsConnected(false);
        console.log('Feed link dropped. Attempting reconnect...');
        eventSource.close();
        setTimeout(connectSSE, 3000);
      };

      eventSource.onmessage = (event) => {
        try {
          const log: EventLog = JSON.parse(event.data);
          if (!log.sandbox_id) return;

          // Append to log terminal
          setLogs(prev => {
            const next = [...prev, log];
            return next.slice(-100); // Limit memory footprint
          });

          // Append to alert timeline if severity triggers
          if (log.type === 'ALERT') {
            setAlerts(prev => [log, ...prev].slice(0, 30));
            triggerVisualAlert(log.category);
          }

          // Trigger particle pulse in interactive graph
          spawnParticle(log.sandbox_id, log.type, log.category);
        } catch (err) {
          // Keepalive ping parser
        }
      };
    };

    connectSSE();
    return () => {
      if (eventSource) eventSource.close();
    };
  }, []);

  // Scroll terminal logs to bottom
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // Spawn visual particle in topology based on category
  const spawnParticle = (_sandboxId: string, type: string, category: string) => {
    if (!canvasRef.current) return;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;

    // Map categories to coordinates
    let targetX = centerX;
    let targetY = centerY;

    const radius = 70;
    const angles: { [key: string]: number } = {
      'FILESYSTEM': -Math.PI / 2, // Top
      'NETWORK': -Math.PI / 6,    // Right-top
      'KERNEL': Math.PI / 6,      // Right-bottom
      'DAEMON': Math.PI / 2,      // Bottom
      'QUOTA_BREACH': (5 * Math.PI) / 6, // Left-bottom
      'EXECUTION_BREACH': (7 * Math.PI) / 6, // Left-top
    };

    // Default target allocation if category unknown
    const angle = angles[category] || angles['KERNEL'];
    targetX = centerX + Math.cos(angle) * radius;
    targetY = centerY + Math.sin(angle) * radius;

    const isLight = document.body.classList.contains('light-theme');
    let color = isLight ? '#007a82' : '#0df'; // Blue syscall particle
    if (type === 'ALERT') {
      color = isLight ? '#b6171e' : '#ff453a'; // Alert red
    }

    particlesRef.current.push({
      x: centerX,
      y: centerY,
      targetX,
      targetY,
      progress: 0,
      speed: 0.04,
      color,
      size: type === 'ALERT' ? 6 : 4
    });
  };

  // Flash a satellite node red upon warning trigger
  const triggerVisualAlert = (category: string) => {
    nodeAlertsRef.current[category] = true;
    setTimeout(() => {
      nodeAlertsRef.current[category] = false;
    }, 1500);
  };

  // Canvas interactive drawing loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    let animationId: number;

    const draw = () => {
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const isLight = document.body.classList.contains('light-theme');
      const redColor = isLight ? '#e76f51' : '#e74c3c';
      const greenColor = isLight ? '#2a9d8f' : '#2ecc71';
      const greyColor = isLight ? '#9e9c97' : '#95a5a6';
      const darkBgColor = isLight ? '#ffffff' : '#161821';
      const darkBorderColor = isLight ? '#dcd9cf' : '#212330';

      // Clear with background opacity to make smooth motion trails
      ctx.fillStyle = isLight ? 'rgba(250, 249, 245, 0.2)' : 'rgba(13, 14, 18, 0.2)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      const centerX = canvas.width / 2;
      const centerY = canvas.height / 2;

      // Draw satellite coordinate nodes
      const radius = 70;
      const nodes = [
        { label: 'Filesystem', cat: 'FILESYSTEM', icon: '📁', angle: -Math.PI / 2 },
        { label: 'Egress Network', cat: 'NETWORK', icon: '🌐', angle: -Math.PI / 6 },
        { label: 'Seccomp Syscalls', cat: 'KERNEL', icon: '🔧', angle: Math.PI / 6 },
        { label: 'Resource Daemon', cat: 'DAEMON', icon: '⚙️', angle: Math.PI / 2 },
        { label: 'Cgroup Quotas', cat: 'QUOTA_BREACH', icon: '📊', angle: (5 * Math.PI) / 6 },
        { label: 'Process Control', cat: 'EXECUTION_BREACH', icon: '⚡', angle: (7 * Math.PI) / 6 },
      ];

      // Draw connecting path links
      ctx.strokeStyle = darkBorderColor;
      ctx.lineWidth = 1.5;
      nodes.forEach(node => {
        const nx = centerX + Math.cos(node.angle) * radius;
        const ny = centerY + Math.sin(node.angle) * radius;
        
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.lineTo(nx, ny);
        ctx.stroke();
      });

      // Draw and update active particles
      const particles = particlesRef.current;
      for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i];
        p.progress += p.speed;

        p.x = centerX + (p.targetX - centerX) * p.progress;
        p.y = centerY + (p.targetY - centerY) * p.progress;

        // Draw particle glow
        ctx.shadowBlur = 10;
        ctx.shadowColor = p.color;
        ctx.fillStyle = p.color;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fill();

        ctx.shadowBlur = 0; // Reset shadow

        if (p.progress >= 1.0) {
          particles.splice(i, 1); // Remove completed pulses
        }
      }

      // Draw Satellite Nodes
      nodes.forEach(node => {
        const nx = centerX + Math.cos(node.angle) * radius;
        const ny = centerY + Math.sin(node.angle) * radius;

        const isAlerting = nodeAlertsRef.current[node.cat];

        // Satellite Glow
        ctx.shadowBlur = isAlerting ? 15 : 4;
        ctx.shadowColor = isAlerting ? redColor : darkBorderColor;

        // Outer rim
        ctx.fillStyle = isAlerting ? redColor : darkBgColor;
        ctx.strokeStyle = isAlerting ? redColor : darkBorderColor;
        ctx.lineWidth = 2;

        ctx.beginPath();
        ctx.arc(nx, ny, 16, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();

        ctx.shadowBlur = 0; // Reset

        // Node Emoji/Icon overlay
        ctx.font = '10px serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(node.icon, nx, ny);

        // Labels
        ctx.font = '8px monospace';
        ctx.fillStyle = isAlerting ? redColor : (isLight ? '#5e5d59' : '#95a5a6');
        ctx.fillText(node.label, nx, ny + 22);
      });

      // Draw Central Sandbox node
      let centerColor = greenColor; // Green running

      if (selectedSandbox) {
        if (selectedSandbox.risk_score === 0) {
          centerColor = greenColor; // Green
        } else if (selectedSandbox.status === 'THROTTLED') {
          centerColor = isLight ? '#e9c46a' : '#f1c40f'; // Orange/Amber
        } else if (selectedSandbox.status === 'QUARANTINED') {
          centerColor = redColor; // Red pulsating
        } else if (selectedSandbox.status === 'TERMINATED') {
          centerColor = greyColor; // Grey
        }
      } else {
        centerColor = isLight ? '#dcd9cf' : '#4f5d75';
      }

      const isStaticState = !selectedSandbox || (selectedSandbox.status === 'TERMINATED' && selectedSandbox.risk_score !== 0) || selectedSandbox.status === 'FAILED';
      const pulseSize = isStaticState ? 17 : 17 + Math.sin(Date.now() / 200) * 1.5;

      ctx.fillStyle = darkBgColor;
      ctx.strokeStyle = centerColor;
      ctx.lineWidth = 2.5;

      ctx.shadowBlur = isStaticState ? 4 : selectedSandbox?.status === 'QUARANTINED' ? 16 : 8;
      ctx.shadowColor = centerColor;

      ctx.beginPath();
      ctx.arc(centerX, centerY, pulseSize, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();

      ctx.shadowBlur = 0; // Reset

      // Center Icon
      ctx.fillStyle = centerColor;
      ctx.font = '11px serif';
      ctx.fillText('🛡️', centerX, centerY);

      // Label below core (truncated if very long to prevent spills out of frame)
      ctx.font = '8.5px monospace';
      ctx.fillStyle = centerColor;
      const canvasLabelId = selectedSandbox 
        ? (selectedSandbox.id.length > 15 ? selectedSandbox.id.substring(0, 12) + '...' : selectedSandbox.id) 
        : 'NONE';
      ctx.fillText(canvasLabelId, centerX, centerY + 28);
      
      animationId = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      cancelAnimationFrame(animationId);
    };
  }, [selectedSandbox?.id, selectedSandbox?.status]);

  // Handle Operations commands
  const handleKill = async (id: string) => {
    try {
      await fetch(`${DAEMON_API}/api/sandbox/kill?id=${id}`, { method: 'POST' });
      fetchSandboxes();
    } catch (e) {
      console.error('Kill error:', e);
    }
  };

  const handleQuarantine = async (id: string) => {
    try {
      await fetch(`${DAEMON_API}/api/sandbox/quarantine?id=${id}`, { method: 'POST' });
      fetchSandboxes();
    } catch (e) {
      console.error('Quarantine error:', e);
    }
  };

  const handleClearHistory = async () => {
    try {
      await fetch(`${DAEMON_API}/api/sandbox/clear`, { method: 'POST' });
    } catch (e) {
      console.error('Failed to clear backend sandbox history:', e);
    }
    // Prune locally immediately as a robust fallback
    setSandboxes(prev => prev.filter(sb => sb.status !== 'TERMINATED' && sb.status !== 'FAILED'));
  };

  const handleRun = async (e: React.FormEvent) => {
    e.preventDefault();
    setRunError('');
    setIsRunningWorkload(true);
    try {
      const resp = await fetch(`${DAEMON_API}/api/sandbox/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: runName,
          workload_path: useCustomCode ? uploadedFileName : runWorkload,
          policy_path: runPolicy,
          code_content: useCustomCode ? runCodeContent : ''
        })
      });
      if (!resp.ok) {
        const message = await resp.text();
        throw new Error(message || 'Backend refused to spawn the workload.');
      }
      const newSb = await resp.json();
      setSandboxes(prev => [...prev.filter(sb => sb.id !== newSb.id), newSb]);
      setSelectedId(newSb.id);
      setShowRunModal(false);
      setRunCodeContent('');
      setUseCustomCode(false);
      setUploadedFileName('');
      setScanResult(null);
      setScanError('');
      fetchSandboxes();
    } catch (e) {
      console.error('Run failed:', e);
      setRunError(e instanceof Error ? e.message : 'Failed to spawn workload.');
    } finally {
      setIsRunningWorkload(false);
    }
  };

  const scanUploadedContent = async (fileName: string, content: string) => {
    if (!content) return;
    setIsScanning(true);
    setScanError('');
    const localResult = localThreatScan(fileName || 'uploaded_payload.py', content);
    setScanResult(localResult);
    try {
      const resp = await fetch(`${DAEMON_API}/api/workload/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          file_name: fileName || 'uploaded_payload.py',
          code_content: content
        })
      });
      if (!resp.ok) {
        const message = await resp.text();
        throw new Error(message || 'Scan failed');
      }
      const result = await resp.json();
      setScanResult(result);
    } catch (err) {
      setScanError(`Backend scan unavailable; showing local scan result. ${err instanceof Error ? err.message : 'Scan failed'}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      handleFileSelection(file);
    }
  };

  const handleFileSelection = (file: File) => {
    setUploadedFileName(file.name);
    setScanResult(null);
    setScanError('');
    setUseCustomCode(true);
    const isPdf = file.name.toLowerCase().endsWith('.pdf');
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string || '';
      setRunCodeContent(content);
      scanUploadedContent(file.name, content);
    };
    reader.onerror = () => {
      setScanError('Unable to read this file. Try a smaller Python, shell, or PDF payload.');
    };
    if (isPdf) {
      reader.readAsDataURL(file);
    } else {
      reader.readAsText(file);
    }
  };

  // COLUMN 1 - Left Panel Component: Registry Panel
  const renderRegistryPanel = () => (
    <div className="comfy-card flex-[1.2]" style={{ minHeight: '180px' }}>
      <div className="comfy-card-header">
        <span className="flex items-center gap-2">
          <Zap size={14} className="text-[var(--accent-cyan)]" />
          Active Workloads Registry
        </span>
        <div className="flex items-center gap-1.5">
          <button 
            title="Upload Threat Payload"
            className="comfy-btn p-1.5" 
            onClick={openFilePicker}
          >
            <Upload size={13} />
          </button>
          <button 
            title="Deploy Local Workload"
            className="comfy-btn p-1.5" 
            onClick={() => {
              setUseCustomCode(false);
              setShowRunModal(true);
            }}
          >
            <Plus size={13} />
          </button>
          <button 
            title="Clear Terminated History"
            className="comfy-btn p-1.5 text-[var(--accent-red)] hover:bg-[rgba(231,76,60,0.08)] hover:border-[var(--accent-red)] transition-all cursor-pointer" 
            onClick={handleClearHistory}
          >
            <Trash2 size={13} />
          </button>
        </div>
      </div>
      
      <div className="workload-scroll-container">
        {sandboxes.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-center text-[var(--text-muted)] font-mono text-xs gap-3">
            <AlertOctagon size={28} />
            NO ACTIVE RUNNING WORKLOADS
            <button 
              className="comfy-btn comfy-btn-primary px-3 py-1.5" 
              onClick={() => {
                setUseCustomCode(false);
                setShowRunModal(true);
              }}
            >
              Spawn Workload
            </button>
          </div>
        ) : (
          sandboxes.map(sb => {
            const isSelected = sb.id === selectedId;
            const isThreat = sb.status === 'QUARANTINED' || sb.risk_score > 60;
            const statusBorderColor = getStatusColor(sb.status, sb.risk_score);
            return (
              <div 
                key={sb.id} 
                className={`registry-card ${sb.risk_score === 0 ? 'running' : sb.status.toLowerCase()} ${isSelected ? 'selected' : ''} ${isThreat && isSelected ? 'danger' : ''}`}
                onClick={() => setSelectedId(sb.id)}
                style={{ borderLeft: `4px solid ${statusBorderColor}` }}
              >
                <div className="registry-card-header flex items-center justify-between gap-2 overflow-hidden">
                  <span className="registry-card-title font-mono truncate max-w-[135px]" title={sb.name}>{sb.name}</span>
                  <span className={`badge flex-shrink-0 ${sb.risk_score === 0 ? 'badge-safe' : `badge-${sb.status.toLowerCase()}`}`}>
                    {sb.risk_score === 0 ? 'SAFE' : sb.status}
                  </span>
                </div>
                <div className="registry-card-metrics">
                  <div className="registry-card-row">
                    <span>Container ID:</span>
                    <span className="font-mono text-[var(--text-primary)] truncate max-w-[120px]" title={sb.id}>{sb.id}</span>
                  </div>
                  <div className="registry-card-row">
                    <span>PID:</span>
                    <span className="text-[var(--accent-cyan)] font-mono">{sb.pid}</span>
                  </div>
                  <div className="registry-card-row">
                    <span>Risk Level:</span>
                    <span className={sb.risk_score > 75 ? 'text-[var(--accent-red)] font-bold' : sb.risk_score > 35 ? 'text-[var(--accent-yellow)]' : 'text-[var(--accent-green)] font-bold'}>
                      {sb.risk_score === 0 ? '0 / 100 (SAFE)' : `${sb.risk_score} / 100`}
                    </span>
                  </div>
                </div>

                {sb.status !== 'TERMINATED' && sb.status !== 'FAILED' && (
                  <div className="registry-card-actions">
                    <button 
                      className="comfy-btn comfy-btn-warning" 
                      onClick={(e) => { e.stopPropagation(); handleQuarantine(sb.id); }}
                      disabled={sb.status === 'QUARANTINED'}
                    >
                      <Lock size={10} /> Quarantine
                    </button>
                    <button 
                      className="comfy-btn comfy-btn-danger" 
                      onClick={(e) => { e.stopPropagation(); handleKill(sb.id); }}
                    >
                      <Trash2 size={10} /> Terminate
                    </button>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );

  // COLUMN 1 - Left Panel Component: Policy configurations
  // COLUMN 1 - Left Panel Component: Policy configurations
  const renderPolicyCard = () => (
    <div className="comfy-card flex-[1]" style={{ minHeight: '180px' }}>
      <div className="comfy-card-header border-b border-[var(--border-color)] pb-2 mb-2">
        <span className="flex items-center gap-1.5 text-[12px] font-bold tracking-wide">
          <Shield size={14} className="text-[var(--accent-cyan)]" />
          Active Policy Architecture
        </span>
      </div>

      <div className="policy-tab-list">
        <button 
          type="button"
          onClick={() => setSelectedPolicyTab('strict.yaml')}
          className={`policy-tab ${selectedPolicyTab === 'strict.yaml' ? 'active' : ''}`}
        >
          strict.yaml
        </button>
        <button 
          type="button"
          onClick={() => setSelectedPolicyTab('low-latency.yaml')}
          className={`policy-tab ${selectedPolicyTab === 'low-latency.yaml' ? 'active' : ''}`}
        >
          low-latency.yaml
        </button>
      </div>

      <div className="grid grid-cols-3 gap-2.5 mb-3 font-mono text-center">
        <div className="bg-[var(--bg-secondary)] border border-[var(--border-color)] p-2 rounded-xl flex flex-col items-center justify-center gap-1 shadow-sm hover:border-[var(--accent-cyan)] transition-all">
          <Clock size={12} className="text-[var(--accent-cyan)]" />
          <span className="text-[7.5px] uppercase font-bold text-[var(--text-secondary)] tracking-wide">Timeout</span>
          <span className="text-[11px] font-bold text-[var(--text-primary)]">{selectedPolicyTab === 'strict.yaml' ? '60s' : '180s'}</span>
        </div>
        <div className="bg-[var(--bg-secondary)] border border-[var(--border-color)] p-2 rounded-xl flex flex-col items-center justify-center gap-1 shadow-sm hover:border-[var(--accent-green)] transition-all">
          <Cpu size={12} className="text-[var(--accent-green)]" />
          <span className="text-[7.5px] uppercase font-bold text-[var(--text-secondary)] tracking-wide">Memory</span>
          <span className="text-[11px] font-bold text-[var(--text-primary)]">{selectedPolicyTab === 'strict.yaml' ? '256MB' : '512MB'}</span>
        </div>
        <div className="bg-[var(--bg-secondary)] border border-[var(--border-color)] p-2 rounded-xl flex flex-col items-center justify-center gap-1 shadow-sm hover:border-[var(--accent-red)] transition-all">
          <Shield size={12} className="text-[var(--accent-red)]" />
          <span className="text-[7.5px] uppercase font-bold text-[var(--text-secondary)] tracking-wide">Denied</span>
          <span className="text-[11px] font-bold text-[var(--accent-red)]">{selectedPolicyTab === 'strict.yaml' ? '5 Sys' : '1 Sys'}</span>
        </div>
      </div>

      <div className={`yaml-comfy-box font-mono flex-grow border-l-2 ${selectedPolicyTab === 'strict.yaml' ? 'border-[var(--accent-cyan)]' : 'border-[var(--accent-yellow)]'}`} style={{ fontSize: '9.5px', maxHeight: '130px', padding: '8px' }}>
        <pre style={{ margin: 0, opacity: 0.9 }}>
          {selectedPolicyTab === 'strict.yaml' ? STRICT_YAML : LOW_LATENCY_YAML}
        </pre>
      </div>
    </div>
  );

  // COLUMN 2 - Center Panel Component: Topology Canvas
  // COLUMN 2 - Center Panel Component: Topology Canvas
  const renderTopologyCard = () => (
    <div className="canvas-card" style={{ height: '300px', flexShrink: 0, padding: '10px 12px', justifyContent: 'flex-start' }}>
      <div className="canvas-header" style={{ position: 'static', alignSelf: 'flex-start', marginBottom: '8px' }}>
        <span className="flex items-center gap-1.5 font-mono text-[9px] text-[var(--text-muted)]">
          <Activity size={10} className="text-[var(--accent-green)] animate-ping" />
          PROCESS INTERCEPT BOUNDARY TOPOLOGY
        </span>
      </div>
      
      <canvas 
        ref={canvasRef} 
        width={420} 
        height={210} 
        className="canvas-interactive"
        style={{ flexGrow: 1, maxHeight: '210px' }}
      />

      {selectedSandbox && (
        <div className="w-full mt-2 bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-xl p-2 font-mono text-[9px] flex justify-between items-center flex-shrink-0">
          <div>
            <div className="text-[var(--text-primary)] font-bold">{selectedSandbox.policy?.sandbox?.name || 'Strict Policy'} bound</div>
            <div className="text-[var(--text-muted)] text-[8px] mt-0.5">CPU: {selectedSandbox.policy?.resources?.cpu || 0} core | Mem: {selectedSandbox.policy?.resources?.memory || 'N/A'}</div>
          </div>
          <div className="flex items-center gap-1 bg-[rgba(231,76,60,0.1)] border border-[rgba(231,76,60,0.2)] px-2 py-0.5 rounded-lg text-[var(--accent-red)]">
            <AlertOctagon size={10} />
            <span>Blocks: {selectedSandbox.violations_count}</span>
          </div>
        </div>
      )}
    </div>
  );

  // COLUMN 2 - Center Panel Component: Threat Payload Scanner
  const renderUploaderCard = () => (
    <div className="comfy-card flex-grow" style={{ minHeight: '160px', overflowY: 'auto' }}>
      <div className="flex flex-col gap-2">
        <div className="comfy-card-header border-b border-[var(--border-color)] pb-1.5 mb-0.5">
          <span className="flex items-center gap-1.5">
            <Eye size={13} className="text-[var(--accent-red)]" />
            Forensic Script Payload Scanner
          </span>
        </div>

        <div className="bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-xl p-2 text-center">
          <div className="flex items-center justify-between gap-3 px-2 py-1">
            <div className="flex items-center gap-2 text-left">
              <div className="p-1.5 rounded bg-[var(--bg-card)] border border-[var(--border-color)] text-[var(--accent-cyan)] shadow-sm">
                <Upload size={14} />
              </div>
              <div className="flex flex-col">
                <span className="text-[11px] font-bold text-[var(--text-primary)]">Upload suspicious files to intercept threats</span>
                <span className="text-[9px] text-[var(--text-secondary)]">Python, Shell scripts or PDF up to 2MB</span>
              </div>
            </div>
            <button
              type="button"
              onClick={openFilePicker}
              className="comfy-btn comfy-btn-primary px-3 py-1 font-mono text-[9.5px]"
              style={{ flex: 'none' }}
            >
              Select File
            </button>
          </div>
        </div>

        {uploadedFileName && (
          <div className="flex items-center justify-between bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-lg px-2.5 py-1.5 text-[9.5px] font-mono">
            <div className="flex items-center gap-1">
              <FileCode size={12} className="text-[var(--accent-green)]" />
              <span className="truncate max-w-[140px] font-bold">{uploadedFileName}</span>
              <span className={`text-[7px] px-1 py-0.5 rounded font-bold uppercase tracking-wider ${
                scanResult?.malicious
                  ? 'text-[var(--accent-red)] bg-[rgba(231,76,60,0.1)] border border-[rgba(231,76,60,0.2)]'
                  : 'text-[var(--accent-green)] bg-[rgba(46,204,113,0.1)] border border-[rgba(46,204,113,0.2)]'
              }`}>
                {scanResult?.malicious ? 'MALWARE' : scanResult?.verdict === 'CLEAN' ? 'SAFE' : 'LOADED'}
              </span>
            </div>
            <button
              type="button"
              onClick={() => {
                setUploadedFileName('');
                setRunCodeContent('');
                setScanResult(null);
                setScanError('');
              }}
              className="text-[var(--text-muted)] hover:text-[var(--accent-red)] p-0.5 cursor-pointer"
            >
              <X size={12} />
            </button>
          </div>
        )}

        {(isScanning || scanResult || scanError) && (
          <div className={`rounded-lg border p-2 text-[9px] font-mono ${
            scanResult?.malicious
              ? 'bg-[rgba(231,76,60,0.06)] border-[var(--accent-red)] text-[var(--accent-red)]'
              : scanResult?.verdict === 'CLEAN'
                ? 'bg-[rgba(42,157,143,0.06)] border-[var(--accent-green)] text-[var(--accent-green)]'
                : 'bg-[rgba(241,196,15,0.06)] border-[var(--accent-yellow)] text-[var(--accent-yellow)]'
          }`}>
            {isScanning && !scanResult ? (
              <div className="font-bold uppercase tracking-wider animate-pulse flex items-center gap-1">
                <Activity size={9} className="animate-spin" /> RUNNING DEEP SANDBOX CONTENT SCANS...
              </div>
            ) : (
              <div className="flex flex-col gap-1">
                {scanResult && (
                  <>
                    <div className="flex items-center justify-between border-b border-[rgba(0,0,0,0.05)] pb-0.5">
                      <span className="font-bold uppercase tracking-wider text-[10px]">
                        {scanResult.malicious ? '⚠️ CRITICAL MALWARE SIGNALS DETECTED' : '✓ SYS_INTEGRITY: SAFE FILE'}
                      </span>
                      <span className="font-bold">Score: {scanResult.score}/100</span>
                    </div>
                    <div className="text-[9px] leading-relaxed text-[var(--text-primary)]">
                      {scanResult.reasons.length > 0 ? scanResult.reasons.join(' • ') : 'No malicious seccomp vectors identified.'}
                    </div>
                  </>
                )}
                {scanError && (
                  <div className="text-[8.5px] text-[var(--accent-red)] border-t border-[rgba(231,76,60,0.15)] pt-1 font-bold">
                    ⚠️ {scanError}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {uploadedFileName && uploadedFileName.toLowerCase().endsWith('.pdf') && (
          <div className="flex flex-col gap-1 bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-xl p-2 font-mono text-[9px] text-[var(--accent-cyan)] relative overflow-hidden">
            <div className="absolute top-0 right-0 p-1 text-[7px] bg-[rgba(231,76,60,0.15)] text-[var(--accent-red)] border-l border-b border-[var(--border-color)] uppercase font-bold tracking-wider">
              ⚠️ Binary Payload
            </div>
            
            <div className="flex items-center gap-1.5 mb-0.5">
              <div className="p-1 rounded bg-[rgba(231,76,60,0.15)] text-[var(--accent-red)]">
                <Shield size={12} />
              </div>
              <div className="text-[var(--text-primary)] font-bold text-[10px] tracking-wide">PDF THREAT CONTEXT COMPILATION</div>
            </div>
            
            <div className="bg-black/35 rounded-lg p-1.5 text-[8px] text-[var(--text-muted)] flex flex-col gap-0.5 border border-[var(--border-color)]">
              <div>{"00000000: 25 50 44 46 2d 31 2e 34  0a 25 e2 e3 cf d3 0a 31  %PDF-1.4.%....1"}</div>
              <div>{"00000010: 20 30 20 6f 62 6a 0a 3c  3c 2f 4c 65 6e 67 74 68   0 obj.<< /Length"}</div>
            </div>
          </div>
        )}
      </div>

      {uploadedFileName && (
        <button
          onClick={() => setShowRunModal(true)}
          className="comfy-btn comfy-btn-primary py-2 w-full font-mono font-bold tracking-wider text-[9.5px] rounded-xl mt-1.5 cursor-pointer"
        >
          <Play size={10} /> ISOLATE PAYLOAD IN SECURE CONTAINER
        </button>
      )}
    </div>
  );

  // COLUMN 3 - Right Panel Component: Resources Diagnostics
  const renderDiagnosticsCard = () => (
    <div className="comfy-card flex-[1]" style={{ minHeight: '140px' }}>
      <div className="comfy-card-header mb-2.5">
        <span>💻 Diagnostics Telemetry</span>
        {selectedSandbox && (
          <span className="font-mono text-[9px] text-[var(--accent-cyan)]">{selectedSandbox.id}</span>
        )}
      </div>

      {selectedSandbox ? (
        <div className="flex flex-col gap-2.5">
          {/* CPU utilization progress */}
          <div className="flex flex-col gap-1.5">
            <div className="flex justify-between text-[11px] font-semibold">
              <span className="flex items-center gap-1.5 text-[var(--text-primary)]">
                <Cpu size={12} className="text-[var(--accent-cyan)]" /> Active CPU Allocation
              </span>
              <span className="font-mono text-[var(--accent-cyan)] font-bold">{selectedSandbox.cpu_usage.toFixed(1)}%</span>
            </div>
            <div className="w-full bg-[var(--bg-secondary)] h-2.5 rounded-full overflow-hidden border border-[var(--border-color)] p-[2px]">
              <div 
                className="h-full rounded-full transition-all duration-300"
                style={{ 
                  width: `${Math.min(selectedSandbox.cpu_usage, 100)}%`,
                  background: 'linear-gradient(90deg, var(--accent-blue), var(--accent-cyan))',
                  boxShadow: '0 0 8px rgba(0, 221, 255, 0.6)'
                }}
              />
            </div>
          </div>

          {/* Memory allocation progress */}
          <div className="flex flex-col gap-1.5">
            <div className="flex justify-between text-[11px] font-semibold">
              <span className="flex items-center gap-1.5 text-[var(--text-primary)]">
                <HardDrive size={12} className="text-[var(--accent-green)]" /> Active Memory Utilization
              </span>
              <span className="font-mono text-[var(--accent-green)] font-bold">
                {(selectedSandbox.memory_usage / (1024 * 1024)).toFixed(1)} MB
              </span>
            </div>
            <div className="w-full bg-[var(--bg-secondary)] h-2.5 rounded-full overflow-hidden border border-[var(--border-color)] p-[2px]">
              <div 
                className="h-full rounded-full transition-all duration-300"
                style={{ 
                  width: `${Math.min((selectedSandbox.memory_usage / (1024 * 1024)) / 2.56, 100)}%`,
                  background: 'linear-gradient(90deg, #1abc9c, var(--accent-green))',
                  boxShadow: '0 0 8px rgba(46, 204, 113, 0.6)'
                }}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-1.5 p-1.5 bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-xl font-mono text-[9px]">
            <div>
              <div className="text-[var(--text-muted)] text-[7px] uppercase">Policy:</div>
              <div className="text-[var(--text-primary)] font-bold mt-0.5 truncate">{selectedSandbox.policy?.sandbox?.name || 'Default strict'}</div>
            </div>
            <div>
              <div className="text-[var(--text-muted)] text-[7px] uppercase">Kernel:</div>
              <div className="text-[var(--accent-green)] font-bold mt-0.5">eBPF Seccomp</div>
            </div>
          </div>
        </div>
      ) : (
        <div className="text-center font-mono text-[9.5px] text-[var(--text-muted)] py-6 bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-xl flex-grow flex items-center justify-center">
          Select workload card to view telemetry.
        </div>
      )}
    </div>
  );

  // COLUMN 3 - Right Panel Component: Threat Chronology Timeline
  const renderTimelineCard = () => (
    <div className="comfy-card flex-[1]" style={{ minHeight: '140px', overflow: 'hidden' }}>
      <div className="comfy-card-header border-b border-[var(--border-color)] pb-1.5 mb-1.5">
        <span className="flex items-center gap-1.5">
          <AlertTriangle size={13} className="text-[var(--accent-red)]" />
          Threat Incidents Chronicle
        </span>
        {alerts.length > 0 && (
          <button 
            onClick={() => setAlerts([])} 
            className="text-[9px] font-mono text-[var(--text-muted)] hover:text-[var(--accent-red)] transition-colors flex items-center gap-1 border border-[var(--border-color)] rounded px-1.5 py-0.5 bg-[var(--bg-primary)] cursor-pointer"
          >
            Clear
          </button>
        )}
      </div>

      <div className="timeline-scroll">
        {alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-[var(--text-muted)] font-mono text-[9.5px] gap-1.5 py-6">
            <CheckCircle size={18} className="text-[var(--accent-green)]" />
            SYS_INTEGRITY: NO DETECTED VIOLATIONS
          </div>
        ) : (
          alerts.map((alert, idx) => (
            <div key={idx} className={`comfy-alert-card ${alert.level === 'WARNING' ? 'warning' : ''}`} style={{ padding: '6px 8px', gap: '8px' }}>
              <AlertTriangle size={12} className={alert.level === 'CRITICAL' ? 'text-[var(--accent-red)]' : 'text-[var(--accent-yellow)]'} />
              <div className="comfy-alert-body">
                <div className="comfy-alert-title-row">
                  <span className="comfy-alert-action font-mono text-[9.5px]">{alert.action}</span>
                  <span className="comfy-alert-time text-[8px]">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                </div>
                <span className="comfy-alert-desc font-mono text-[8.5px]">{alert.message}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );

  // COLUMN 3 - Right Panel Component: scrolling trace console
  const renderSyscallTerminalCard = () => (
    <div className="comfy-terminal-wrap" style={{ height: '160px' }}>
      <div className="comfy-terminal-header">
        <span>REAL-TIME SYSTEM CALLTRACE CONSOLE</span>
        <div className="flex items-center gap-1.5">
          {logs.length > 0 && (
            <button 
              onClick={() => setLogs([])} 
              className="text-[8px] font-mono text-[var(--text-muted)] hover:text-[var(--accent-red)] transition-colors border border-[var(--border-color)] rounded px-1.5 py-0.5 bg-[var(--bg-primary)] cursor-pointer"
            >
              Clear
            </button>
          )}
          <span className="text-[8px] px-1.5 py-0.5 bg-[var(--bg-primary)] rounded border border-[var(--border-color)] text-[var(--text-muted)]">PAGER=cat</span>
        </div>
      </div>
      <div className="comfy-terminal-body">
        {logs.length === 0 ? (
          <div className="text-[var(--text-muted)] text-center mt-12 font-mono text-[9px]">Awaiting kernel syscall connection...</div>
        ) : (
          logs.map((log, index) => {
            const isAlert = log.type === 'ALERT';
            const isSystem = log.type === 'SYSTEM';
            const formattedTime = new Date(log.timestamp).toLocaleTimeString();
            const shortId = log.sandbox_id.length > 12 ? log.sandbox_id.substring(0, 10) + '...' : log.sandbox_id;
            return (
              <div key={index} className="trace-line text-[9px]">
                <span className="trace-time">[{formattedTime}] </span>
                <span className="trace-id" title={log.sandbox_id}>{shortId} </span>
                {isSystem ? (
                  <span className="text-purple-400 font-bold">[DAEMON] {log.message}</span>
                ) : (
                  <>
                    <span className="trace-sys">{log.action}() </span>
                    <span className={isAlert ? 'trace-err' : 'trace-msg'}>{log.message}</span>
                  </>
                )}
              </div>
            );
          })
        )}
        <div ref={logsEndRef} />
      </div>
    </div>
  );

  // Deployment form modal helper
  const renderRunModal = () => (
    <div className="modal-overlay">
      <div className="modal-content">
        <div className="comfy-card-header border-b border-[var(--border-color)] p-5">
          <span className="flex items-center gap-2 text-[var(--text-primary)]">
            <Play size={14} className="text-[var(--accent-green)]" /> Deploy Secure Container
          </span>
          <button className="text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer" onClick={() => setShowRunModal(false)}>
            <X size={16} />
          </button>
        </div>
        
        <form onSubmit={handleRun} className="p-5 flex flex-col gap-4">
          <div className="form-group">
            <label>Sandbox Identifier Name</label>
            <input 
              type="text" 
              value={runName} 
              onChange={e => setRunName(e.target.value)}
              placeholder="e.g. malware-python-demo"
              required
            />
          </div>

          <div className="run-mode-tabs">
            <button 
              type="button"
              className={`run-mode-tab ${!useCustomCode ? 'active' : ''}`}
              onClick={() => setUseCustomCode(false)}
            >
              Default Workload
            </button>
            <button 
              type="button"
              className={`run-mode-tab ${useCustomCode ? 'active' : ''}`}
              onClick={() => setUseCustomCode(true)}
            >
              Upload Threat Script
            </button>
          </div>

          {!useCustomCode ? (
            <div className="form-group">
              <label>Target Workload Python Script Path</label>
              <input 
                type="text" 
                value={runWorkload} 
                onChange={e => setRunWorkload(e.target.value)}
                placeholder="demo/malware.py"
                required={!useCustomCode}
              />
            </div>
          ) : (
            <div className="form-group flex flex-col gap-3">
              <textarea
                rows={5}
                value={runCodeContent}
                onChange={e => {
                  setRunCodeContent(e.target.value);
                  setUploadedFileName('');
                  setScanResult(null);
                  setScanError('');
                }}
                placeholder="Write or paste your custom Python threat script here, or select 'Select Target File' in the Forensics tab..."
                className="w-full bg-[var(--bg-primary)] border border-[var(--border-color)] rounded-md p-3 font-mono text-xs text-[var(--accent-cyan)] outline-none resize-none transition-all"
                required={useCustomCode}
              />
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={openFilePicker}
                  className="comfy-btn comfy-btn-primary px-3 py-1.5 text-[11px]"
                >
                  <Upload size={12} /> Select File
                </button>
                <button
                  type="button"
                  onClick={() => scanUploadedContent(uploadedFileName || `${runName || 'manual_payload'}.py`, runCodeContent)}
                  disabled={!runCodeContent || isScanning}
                  className="comfy-btn px-3 py-1.5 text-[11px]"
                >
                  {isScanning ? 'Scanning...' : 'Scan File'}
                </button>
                {uploadedFileName && (
                  <span className="font-mono text-[9px] text-[var(--text-muted)] truncate max-w-[180px]">
                    {uploadedFileName}
                  </span>
                )}
              </div>
            </div>
          )}

          <div className="form-group">
            <label>Declarative Security YAML Profile</label>
            <input 
              type="text" 
              value={runPolicy} 
              onChange={e => setRunPolicy(e.target.value)}
              placeholder="demo/strict.yaml"
              required
            />
          </div>

          <div className="flex gap-4 mt-2">
            <button type="button" className="comfy-btn flex-1 py-2.5" onClick={() => setShowRunModal(false)}>
              Cancel
            </button>
            <button type="submit" className="comfy-btn comfy-btn-primary flex-1 py-2.5" disabled={isRunningWorkload || (useCustomCode && (!runCodeContent || isScanning))}>
              <Play size={12} /> {isRunningWorkload ? 'Spawning...' : 'Spawn Container'}
            </button>
          </div>
          {runError && (
            <div className="run-error">
              {runError}
            </div>
          )}
        </form>
      </div>
    </div>
  );

  return (
    <div className="app-layout">
      {/* Hidden robust root file input that never unmounts */}
      <input 
        type="file" 
        id="threat-file-input"
        ref={fileInputRef}
        accept=".py,.sh,.pdf"
        style={{ display: 'none' }}
        onChange={handleFileChange}
      />

      {/* Top Console Header Bar */}
      <header className="console-header">
        <div className="header-brand">
          <Shield className="brand-logo" size={26} />
          <span className="brand-text">AEGISCORE SOC HUD</span>
          <span className={`badge ${isConnected ? 'badge-running' : 'badge-quarantined'}`} style={{ marginLeft: '10px' }}>
            Daemon: {isConnected ? 'Online' : 'Offline'}
          </span>
        </div>

        <div className="header-actions">
          {/* Stats Bar */}
          <div className="header-stats-bar">
            <div className="header-stat-node">
              <span className="header-stat-val text-[var(--accent-green)] font-mono">
                {sandboxes.filter(s => s.status === 'RUNNING' || s.risk_score === 0).length}
              </span>
              <span className="header-stat-label">Isolated</span>
            </div>
            <div className="header-stat-node">
              <span className="header-stat-val text-[var(--accent-red)] font-mono">
                {sandboxes.reduce((acc, s) => acc + s.violations_count, 0)}
              </span>
              <span className="header-stat-label">Blocks</span>
            </div>
            <div className="header-stat-node">
              <span className="header-stat-val text-[var(--accent-yellow)] font-mono">
                {sandboxes.length > 0 ? Math.max(...sandboxes.map(s => s.risk_score)) : 0}%
              </span>
              <span className="header-stat-label">Max Risk</span>
            </div>
          </div>

          {/* Quick Root Upload Button Trigger */}
          <button 
            onClick={openFilePicker}
            className="comfy-btn comfy-btn-primary py-2 px-3 flex items-center justify-center gap-2"
            title="Upload Threat Payload"
          >
            <Upload size={14} /> <span>Upload Threat</span>
          </button>

          {/* Theme Toggler */}
          <button 
            onClick={toggleTheme}
            className="flex items-center justify-center p-2 rounded-lg border border-[var(--border-color)] bg-[var(--bg-card)] text-[var(--text-primary)] hover:bg-[var(--bg-card-hover)] cursor-pointer"
            title="Toggle Theme Mode"
            style={{ width: '38px', height: '38px' }}
          >
            {isLightTheme ? <Moon size={16} className="text-[var(--accent-cyan)]" /> : <Sun size={16} className="text-[var(--accent-cyan)]" />}
          </button>
        </div>
      </header>

      {/* Main 3-Column HUD Grid */}
      <div className="dashboard-3col-grid">
        
        {/* ==================== COLUMN 1 (LEFT PANEL) ==================== */}
        <div className="panel-col">
          {renderRegistryPanel()}
          {renderPolicyCard()}
        </div>

        {/* ==================== COLUMN 2 (CENTER PANEL) ==================== */}
        <div className="panel-col" style={{ flexGrow: 1 }}>
          {renderTopologyCard()}
          {renderUploaderCard()}
        </div>

        {/* ==================== COLUMN 3 (RIGHT PANEL) ==================== */}
        <div className="panel-col">
          {renderDiagnosticsCard()}
          {renderTimelineCard()}
          {renderSyscallTerminalCard()}
        </div>

      </div>

      {/* Deployment Modal Overlay */}
      {showRunModal && renderRunModal()}
    </div>
  );
}
