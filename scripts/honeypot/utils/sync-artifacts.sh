export AWS_SHARED_CREDENTIALS_FILE="/etc/vector/.aws/credentials"
AWS_BIN="/usr/bin/aws"
BUCKET="s3://cowrie-vector-logs-a570fac6"
REGION="us-east-1"
echo "[+] Starting artifact sync to S3..."
$AWS_BIN s3 sync /home/cowrie/cowrie/var/lib/cowrie/downloads/ $BUCKET/evidence/malware/ \
    --region $REGION \
    --exclude ".gitignore"
$AWS_BIN s3 sync /home/cowrie/cowrie/var/lib/cowrie/tty/ $BUCKET/evidence/tty/ \
    --region $REGION \
    --exclude ".gitignore"
echo "[SUCCESS] Sync complete at \$(date)"