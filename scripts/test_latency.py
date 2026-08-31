import time
import subprocess
import requests
import json

print("[TEST] Triggering Option 2 (Hydra Brute Force)...")
t0 = time.perf_counter()

# Run the attack script
proc = subprocess.run(
    ["powershell", "-ExecutionPolicy", "Bypass", "-File", ".\\scripts\\demo_attacks.ps1", "-Choice", "2"],
    capture_output=True,
    text=True
)
t_attack_done = time.perf_counter()
print(f"[TEST] Attack process finished in {t_attack_done - t0:.2f}s.")

# Poll for threat
t_found = None
while time.perf_counter() - t0 < 30:
    try:
        r = requests.get("http://localhost:8000/api/threats", timeout=2)
        threats = r.json()
        if threats and len(threats) > 0:
            t_found = time.perf_counter()
            break
    except Exception:
        pass
    time.sleep(0.2)

if t_found:
    print(f"[TEST] Threat appeared in {t_found - t0:.2f}s total ({t_found - t_attack_done:.2f}s after attack finished)!")
else:
    print("[TEST] Timeout waiting for threat.")

threats = requests.get("http://localhost:8000/api/threats").json()
print("\n=== /api/threats JSON ===")
print(json.dumps(threats, indent=2))

logs = requests.get("http://localhost:8000/api/logs").json()
print("\n=== /api/logs JSON ===")
print(json.dumps(logs, indent=2))
