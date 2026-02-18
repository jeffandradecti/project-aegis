COWRIE_HOME="/home/cowrie/cowrie"
LOG_FILE="$COWRIE_HOME/var/log/cowrie/cowrie.json"
VECTOR_DATA_DIR="/var/lib/vector"
echo "[$(date)] --- STARTING HONEYPOT BOOT AUDIT ---"
if ! iptables -t nat -L PREROUTING -n | grep -q "redir ports 22222"; then
    echo "[+] Applying Port 22 -> 22222 redirect rule..."
    iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 22222
fi
mkdir -p "$VECTOR_DATA_DIR"
chown vector:vector "$VECTOR_DATA_DIR"
if [ -f "$LOG_FILE" ] && grep -Pq '\x00' "$LOG_FILE"; then
    echo "[!] Corrupted log detected. Truncating file and clearing Vector cache..."
    truncate -s 0 "$LOG_FILE"
    rm -rf "$VECTOR_DATA_DIR"/*
fi
echo "[*] Starting Cowrie as cowrie user..."
sudo -u cowrie -H bash -c "cd $COWRIE_HOME && source cowrie-env/bin/activate && cowrie start"
echo "[*] Restarting Vector..."
systemctl restart vector
sleep 5
if ss -tulpn | grep -q ":22222"; then
    echo "[SUCCESS] Cowrie is active on port 22222."
else
    echo "[ERROR] Cowrie process did not bind to port. Check cowrie.log"
    exit 1
fi
echo "[$(date)] --- BOOT AUDIT COMPLETE ---"