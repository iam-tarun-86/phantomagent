import time
import subprocess
import requests
import json

print("=== EXECUTING 3 CONSECUTIVE REFACTORED PIPELINE RUNS ===")

runs = []

for i in range(1, 4):
    print(f"\n--- [RUN {i}/3] ---")
    print("[1] Restarting backend...")
    subprocess.run(
        ["powershell", "-Command", "Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"],
        capture_output=True
    )
    time.sleep(1)
    
    backend_proc = subprocess.Popen(
        [r".venv\Scripts\python.exe", "run.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
    # Wait for backend to be ready
    ready = False
    for _ in range(15):
        try:
            r = requests.get("http://localhost:8000/api/threats", timeout=1)
            if r.status_code == 200:
                ready = True
                break
        except Exception:
            pass
        time.sleep(0.5)
        
    if not ready:
        print("[ERROR] Backend not ready.")
        continue
    
    print("[2] Executing Hydra brute force scenario...")
    t0 = time.perf_counter()
    subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-File", r".\scripts\demo_attacks.ps1", "-Choice", "2"],
        capture_output=True,
        text=True
    )
    t_attack = time.perf_counter()
    
    # Poll for threat
    threat = None
    for _ in range(50):
        try:
            r = requests.get("http://localhost:8000/api/threats", timeout=1)
            data = r.json()
            if data and len(data) > 0:
                threat = data[0]
                break
        except Exception:
            pass
        time.sleep(0.3)
        
    t_done = time.perf_counter()
    
    if threat:
        print(f"[RUN {i} SUCCESS] (Total: {t_done - t0:.2f}s, Inference: {t_done - t_attack:.2f}s)")
        print(f"  Severity      : {threat.get('severity')}")
        print(f"  Status        : {threat.get('status')}")
        print(f"  Attack Pattern: {threat.get('attack_pattern')}")
        print(f"  Explanation   : {threat.get('explanation')}")
        runs.append({
            "run": i,
            "latency": t_done - t0,
            "threat": threat
        })
    else:
        print(f"[RUN {i} FAILED] Timeout.")
        
    backend_proc.terminate()
    try:
        backend_proc.wait(timeout=2)
    except Exception:
        backend_proc.kill()

with open("scripts/3runs_result.json", "w") as f:
    json.dump(runs, f, indent=2)

print("\nAll 3 runs completed.")
