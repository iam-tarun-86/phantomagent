import time
import subprocess
import requests
import json

print("=== STARTING 5 CONSECUTIVE BRUTE FORCE CONSISTENCY RUNS ===")

results = []

for run_idx in range(1, 6):
    print(f"\n--- [RUN {run_idx}/5] ---")
    
    # Restart backend to guarantee fresh state
    print("[1] Restarting backend server...")
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
    
    # Wait for backend to be responsive
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
        print("[ERROR] Backend failed to start.")
        continue
    
    print("[2] Executing Hydra brute force scenario...")
    t0 = time.perf_counter()
    
    # Run demo_attacks.ps1 Choice 2
    subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-File", r".\scripts\demo_attacks.ps1", "-Choice", "2"],
        capture_output=True,
        text=True
    )
    t_attack_done = time.perf_counter()
    
    # Poll for threat
    t_found = None
    threat_data = None
    
    for _ in range(50):
        try:
            r = requests.get("http://localhost:8000/api/threats", timeout=1)
            threats = r.json()
            if threats and len(threats) > 0:
                t_found = time.perf_counter()
                threat_data = threats[0]
                break
        except Exception:
            pass
        time.sleep(0.3)
    
    if t_found and threat_data:
        elapsed = t_found - t0
        inference_latency = t_found - t_attack_done
        sev = threat_data.get("severity")
        exp = threat_data.get("explanation")
        pat = threat_data.get("attack_pattern")
        ttype = threat_data.get("type")
        status = threat_data.get("status")
        
        print(f"[RESULT RUN {run_idx}] Total Time: {elapsed:.2f}s (Inference: {inference_latency:.2f}s)")
        print(f"  Type          : {ttype}")
        print(f"  Severity      : {sev}")
        print(f"  Status        : {status}")
        print(f"  Attack Pattern: {pat}")
        print(f"  Explanation   : {exp}")
        
        results.append({
            "run": run_idx,
            "total_time": elapsed,
            "inference_time": inference_latency,
            "severity": sev,
            "type": ttype,
            "status": status,
            "attack_pattern": pat,
            "explanation": exp,
            "full_json": threat_data
        })
    else:
        print(f"[ERROR RUN {run_idx}] Timeout waiting for threat.")
    
    # Terminate backend process for next run
    backend_proc.terminate()
    try:
        backend_proc.wait(timeout=2)
    except Exception:
        backend_proc.kill()

print("\n" + "="*70)
print("=== 5-RUN CONSISTENCY SUMMARY ===")
print("="*70)

if results:
    avg_total = sum(r["total_time"] for r in results) / len(results)
    avg_infer = sum(r["inference_time"] for r in results) / len(results)
    print(f"Average Total Latency     : {avg_total:.2f}s")
    print(f"Average Inference Latency : {avg_infer:.2f}s\n")
    
    for r in results:
        print(f"Run {r['run']}: Severity {r['severity']} ({r['status']}) -> Explanation: \"{r['explanation']}\" [Latency: {r['total_time']:.2f}s]")
else:
    print("No successful results.")

# Save results JSON
with open("scripts/5runs_result.json", "w") as f:
    json.dump(results, f, indent=2)
