$ServerIP = "xxx.xxx.xxx.xxx"
$SSHPort = 2222
$SSHUser = "root"
$KeyPath = "..\.ssh\honeypot"
$RemoteCommands = @'
set -e
# --- INTERNAL VARIABLES ---
LOG_FILE="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
VECTOR_CONFIG="/etc/vector/vector.yaml"
VECTOR_DATA_DIR="/var/lib/vector"
DISK_THRESHOLD=90
echo "==============================================="
echo "   COWRIE & VECTOR AUTOMATED HEALTH CHECK"
echo "   $(date)"
echo "==============================================="
# [A] CHECK DISK SPACE (Prevent Null Bytes)
# ----------------------------------------
DISK_USAGE=$(df / | grep / | awk '{ print $5 }' | sed 's/%//g')
if [ "$DISK_USAGE" -gt "$DISK_THRESHOLD" ]; then
    echo "[CRITICAL] Disk usage is at ${DISK_USAGE}%. Cleaning up old logs..."
    find /home/cowrie/cowrie/var/log/cowrie/ -name "cowrie.json.*" -mtime +7 -delete
    docker system prune -f > /dev/null 2>&1 || true
else
    echo "[OK] Disk usage is healthy (${DISK_USAGE}%)"
fi
# [B] CHECK & FIX VECTOR CONFIG (The "Safe Parse" Patch)
# ----------------------------------------
if [ -f "$VECTOR_CONFIG" ]; then
    if grep -q "parse_json!(" "$VECTOR_CONFIG"; then
        echo "[WARN] Found unsafe 'parse_json!' in Vector config. Patching..."
        # Replace the hard-fail line with a safe error-handling block
        sed -i 's/.*parse_json!(.message).*/      parsed, err = parse_json(.message)\n      if err != null { abort }\n      . = parsed/g' "$VECTOR_CONFIG"
        echo "[FIX] Config patched. Restarting Vector..."
        systemctl restart vector
    else
        echo "[OK] Vector config is safe (using error handling)."
    fi
else
    echo "[WARN] Vector config not found at $VECTOR_CONFIG"
fi
# [C] CHECK LOG INTEGRITY (The Null Byte Fix)
# ----------------------------------------
if [ -f "$LOG_FILE" ]; then
    # Check if file contains null bytes (invisible ^@ symbols)
    if grep -Pq '\x00' "$LOG_FILE"; then
        echo "[FAIL] Corrupted log file detected (Null Bytes). Truncating..."
        true > "$LOG_FILE"
        # Force Vector to re-scan by clearing the checkpoint cache
        echo "[FIX] Clearing Vector checkpoints..."
        systemctl stop vector
        rm -rf "$VECTOR_DATA_DIR"/*
        systemctl start vector
    else
        echo "[OK] Cowrie log file is valid (no corruption detected)."
    fi
else
    echo "[WARN] Log file not found at $LOG_FILE"
fi
# [D] SERVICE STATUS CHECK
# ----------------------------------------
# Check Vector
if systemctl is-active --quiet vector; then
    echo "[OK] Vector service is RUNNING."
else
    echo "[FAIL] Vector service is DOWN. Restarting..."
    # Ensure data dir exists before starting
    mkdir -p "$VECTOR_DATA_DIR" && chown vector:vector "$VECTOR_DATA_DIR"
    systemctl restart vector
fi
# Check Cowrie (Process check via pgrep)
if pgrep -f "twistd.*cowrie" > /dev/null; then
    echo "[OK] Cowrie process is RUNNING."
else
    echo "[FAIL] Cowrie process is DOWN. Restarting via Virtual Env..."
    if id "cowrie" &>/dev/null; then
        sudo -u cowrie -H bash -c '
            cd /home/cowrie/cowrie
            source cowrie-env/bin/activate
            ./bin/cowrie stop || true
            ./bin/cowrie start
        '
    else
        echo "[CRITICAL] User 'cowrie' not found. Cannot start honeypot."
    fi
fi
# [E] CONNECTIVITY CHECK (Port Forwarding)
# ----------------------------------------
if iptables -t nat -L PREROUTING -n | grep -q "redir ports 22222"; then
    echo "[OK] Port forwarding (22 -> 22222) is ACTIVE."
else
    echo "[FAIL] Port forwarding missing. Re-applying rule..."
    iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 22222
fi
echo "==============================================="
echo "   HEALTH CHECK COMPLETE"
echo "==============================================="
'@
if (-not (Test-Path $KeyPath))
{
    Write-Error "SSH Key not found at $KeyPath"
    exit
}
$RemoteCommandsLF = $RemoteCommands -replace "`r`n", "`n"
Write-Host "[*] Connecting to $ServerIP..." -ForegroundColor Cyan
$RemoteCommandsLF | ssh -i $KeyPath -p $SSHPort -o StrictHostKeyChecking=no "$SSHUser@$ServerIP" "bash -s"
if ($LASTEXITCODE -eq 0)
{
    Write-Host "[+] Remote maintenance finished successfully." -ForegroundColor Green
}
else
{
    Write-Host "[-] Remote maintenance encountered a network or SSH error (Code: $LASTEXITCODE)" -ForegroundColor Red
}