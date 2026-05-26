#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

TARGET_DIR="$SCRIPT_DIR"
while [[ "$TARGET_DIR" != "/" && ! -f "$TARGET_DIR/.env" ]]; do
    TARGET_DIR="$(dirname "$TARGET_DIR")"
done
PROJECT_ROOT="$TARGET_DIR"
ENV_FILE="$PROJECT_ROOT/.env"

if [ -f "$ENV_FILE" ]; then
    # shellcheck disable=SC2046
    export $(grep -v '^#' "$ENV_FILE" | tr -d '\r' | xargs)
else
    echo "CRITICAL: .env file missing. Searched up to $PROJECT_ROOT"
    exit 1
fi

if [ -z "$SERVER_IP" ]; then
    echo "CRITICAL: SERVER_IP is missing from your .env file."
    exit 1
fi

SSH_PORT=2222
SSH_USER="root"
KEY_PATH="$PROJECT_ROOT/.ssh/honeypot"

if [ ! -f "$KEY_PATH" ]; then
    echo "SSH Key not found at $KEY_PATH" >&2
    exit 1
fi

echo "[*] Connecting to $SERVER_IP..."

ssh -i "$KEY_PATH" -p "$SSH_PORT" -o StrictHostKeyChecking=no "$SSH_USER@$SERVER_IP" 'bash -s' << 'EOF'
set -e

LOG_FILE="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
VECTOR_CONFIG="/etc/vector/vector.yaml"
VECTOR_DATA_DIR="/var/lib/vector"
DISK_THRESHOLD=90

echo "==============================================="
echo "   COWRIE & VECTOR AUTOMATED HEALTH CHECK"
echo "   $(date)"
echo "==============================================="

DISK_USAGE=$(df / | grep / | awk '{ print $5 }' | sed 's/%//g')
if [ "$DISK_USAGE" -gt "$DISK_THRESHOLD" ]; then
    echo "[CRITICAL] Disk usage is at ${DISK_USAGE}%. Cleaning up old logs..."
    find /home/cowrie/cowrie/var/log/cowrie/ -name "cowrie.json.*" -mtime +7 -delete
    docker system prune -f > /dev/null 2>&1 || true
else
    echo "[OK] Disk usage is healthy (${DISK_USAGE}%)"
fi

if [ -f "$VECTOR_CONFIG" ]; then
    if grep -q "parse_json!(" "$VECTOR_CONFIG"; then
        echo "[WARN] Found unsafe 'parse_json!' in Vector config. Patching..."
        sed -i 's/.*parse_json!(.message).*/      parsed, err = parse_json(.message)\n      if err != null { abort }\n      . = parsed/g' "$VECTOR_CONFIG"
        echo "[FIX] Config patched. Restarting Vector..."
        systemctl restart vector
    else
        echo "[OK] Vector config is safe (using error handling)."
    fi
else
    echo "[WARN] Vector config not found at $VECTOR_CONFIG"
fi

if [ -f "$LOG_FILE" ]; then
    if grep -Pq '\x00' "$LOG_FILE"; then
        echo "[FAIL] Corrupted log file detected (Null Bytes). Truncating..."
        true > "$LOG_FILE"
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

if systemctl is-active --quiet vector; then
    echo "[OK] Vector service is RUNNING."
else
    echo "[FAIL] Vector service is DOWN. Restarting..."
    mkdir -p "$VECTOR_DATA_DIR" && chown vector:vector "$VECTOR_DATA_DIR"
    systemctl restart vector
fi

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

if iptables -t nat -L PREROUTING -n | grep -q "redir ports 22222"; then
    echo "[OK] Port forwarding (22 -> 22222) is ACTIVE."
else
    echo "[FAIL] Port forwarding missing. Re-applying rule..."
    iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 22222
fi

echo "==============================================="
echo "   HEALTH CHECK COMPLETE"
echo "==============================================="
EOF

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "[+] Remote maintenance finished successfully."
else
    echo "[-] Remote maintenance encountered a network or SSH error (Code: $EXIT_CODE)"
fi