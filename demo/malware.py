# spyware_simulator.py
# SAFE Spyware Simulation for Sandbox Demonstration
# Educational use only — non-destructive

import os
import time
import platform

print("=" * 60)
print(" SAFE SPYWARE SIMULATION STARTED ")
print("=" * 60)

# ---------------------------------------------------
# 1. Collect Basic System Information
# ---------------------------------------------------

print("\n[+] Collecting system information...\n")

system_info = {
    "OS": platform.system(),
    "OS Version": platform.version(),
    "Machine": platform.machine(),
    "Processor": platform.processor(),
}

for key, value in system_info.items():
    print(f"{key}: {value}")
    time.sleep(0.5)

# ---------------------------------------------------
# 2. Attempt Access to Sensitive Files
# ---------------------------------------------------

print("\n[+] Attempting to access sensitive files...\n")

targets = [
    "/etc/passwd",
    "/root/.bash_history",
    "/home/admin/passwords.txt"
]

for target in targets:
    try:
        with open(target, "r") as f:
            print(f"[ACCESS GRANTED] {target}")
    except Exception as e:
        print(f"[BLOCKED] Access denied to {target}")
        print(f"Reason: {e}\n")

# ---------------------------------------------------
# 3. Simulate Keylogging Activity
# ---------------------------------------------------

print("[+] Simulating keylogging behavior...\n")

fake_keys = ["H", "e", "l", "l", "o", "1", "2", "3"]

for key in fake_keys:
    print(f"[CAPTURED KEY] {key}")
    time.sleep(0.3)

print("\n[WARNING] Suspicious input monitoring detected!")

# ---------------------------------------------------
# 4. Simulate Screenshot Collection
# ---------------------------------------------------

print("\n[+] Attempting screenshot capture...\n")

try:
    print("[SIMULATION] Screenshot request triggered")
    time.sleep(1)
    print("[BLOCKED] Screenshot access denied by sandbox")

except Exception as e:
    print(f"[BLOCKED] Screenshot action failed: {e}")

# ---------------------------------------------------
# 5. Simulate Data Exfiltration
# ---------------------------------------------------

print("\n[+] Attempting external data transfer...\n")

try:
    response = os.system("ping -c 1 example.com")

    if response == 0:
        print("[WARNING] External communication allowed")
    else:
        print("[BLOCKED] Network transfer denied")

except Exception as e:
    print(f"[BLOCKED] Network request failed: {e}")

# ---------------------------------------------------
# 6. Simulate Persistence Attempt
# ---------------------------------------------------

print("\n[+] Attempting persistence mechanism...\n")

try:
    with open("/tmp/startup_service.sh", "w") as f:
        f.write("# fake persistence service")

    print("[WARNING] Persistence file created")

except Exception as e:
    print(f"[BLOCKED] Persistence creation denied: {e}")

# ---------------------------------------------------
# END
# ---------------------------------------------------

print("\n" + "=" * 60)
print(" SAFE SPYWARE SIMULATION COMPLETE ")
print("=" * 60)