#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

TARGET_DIR="$SCRIPT_DIR"
while [[ "$TARGET_DIR" != "/" && ! -f "$TARGET_DIR/.env" ]]; do
    TARGET_DIR="$(dirname "$TARGET_DIR")"
done
PROJECT_ROOT="$TARGET_DIR"

OUTPUT_DIR="$PROJECT_ROOT/results"
ENV_FILE="$PROJECT_ROOT/.env"

if [ -f "$ENV_FILE" ]; then
    # shellcheck disable=SC2046
    export $(grep -v '^#' "$ENV_FILE" | tr -d '\r' | xargs)
else
    echo "CRITICAL: .env file missing at $ENV_FILE"
    exit 1
fi

if [ -z "$BUCKET_NAME" ] || [ -z "$PREFIX" ] || [ -z "$AWS_PROFILE" ] || [ -z "$FUNCTION_NAME" ]; then
    echo "CRITICAL: Missing required variables in .env file."
    exit 1
fi

# ==========================================
# UNIVERSAL AWS CLI DETECTION
# ==========================================
if command -v aws &> /dev/null; then
    AWS_CMD="aws"
    NEEDS_WSLPATH=false
elif command -v aws.exe &> /dev/null; then
    AWS_CMD="aws.exe"
    # Verify we are actually inside WSL to safely use wslpath
    if grep -qi microsoft /proc/version 2>/dev/null; then
        NEEDS_WSLPATH=true
    else
        NEEDS_WSLPATH=false
    fi
else
    echo "CRITICAL: AWS CLI not found. Please install natively or ensure aws.exe is in PATH."
    exit 1
fi
# ==========================================

echo "Gathering baseline using profile: $AWS_PROFILE"
EXISTING_FILES=$($AWS_CMD s3api list-objects-v2 --bucket "$BUCKET_NAME" --prefix "$PREFIX" --profile "$AWS_PROFILE" --query "Contents[].Key" --output text 2>/dev/null | tr '\t' '\n' | tr -d '\r')

echo "Triggering Lambda function..."
TMP_OUT="/tmp/invoke_result_$$.json"
$AWS_CMD lambda invoke --function-name "$FUNCTION_NAME" --invocation-type Event --profile "$AWS_PROFILE" --cli-binary-format raw-in-base64-out --payload "{}" "$TMP_OUT" > /dev/null 2>&1
rm -f "$TMP_OUT"

echo "Polling S3 for the new .iso file (Timeout: 60 seconds)..."
TIMEOUT=60
WAIT_TIME=5
ELAPSED=0
NEW_ISO_KEY=""

while [ $ELAPSED -lt $TIMEOUT ]; do
    sleep $WAIT_TIME
    ELAPSED=$((ELAPSED + WAIT_TIME))
    echo "Checking S3... ($ELAPSED/$TIMEOUT seconds)"

    CURRENT_FILES=$($AWS_CMD s3api list-objects-v2 --bucket "$BUCKET_NAME" --prefix "$PREFIX" --profile "$AWS_PROFILE" --query "Contents[].Key" --output text 2>/dev/null | tr '\t' '\n' | tr -d '\r')

    for file in $CURRENT_FILES; do
        if [[ "$file" == *.iso ]]; then
            if ! echo "$EXISTING_FILES" | grep -Fqw "$file"; then
                NEW_ISO_KEY="$file"
                break 2
            fi
        fi
    done
done

if [ -n "$NEW_ISO_KEY" ]; then
    echo -e "\n[+] Found new forensics package: $NEW_ISO_KEY"
    mkdir -p "$OUTPUT_DIR"

    FILE_NAME=$(basename "$NEW_ISO_KEY")
    DESTINATION="$OUTPUT_DIR/$FILE_NAME"
    DL_PATH="$DESTINATION"

    # If falling back to Windows AWS CLI inside WSL, translate the path
    if [ "$NEEDS_WSLPATH" = true ]; then
        DL_PATH=$(wslpath -w "$DESTINATION")
    fi

    echo "Downloading directly to /results/ directory..."
    $AWS_CMD s3 cp "s3://$BUCKET_NAME/$NEW_ISO_KEY" "$DL_PATH" --profile "$AWS_PROFILE"
    echo "[+] Success! File saved at: $DESTINATION"
else
    echo -e "\n[-] Timeout reached. Fetching recent CloudWatch logs for Lambda errors..."
    echo "================ LAMBDA LOGS ================"
    $AWS_CMD logs tail "/aws/lambda/$FUNCTION_NAME" --profile "$AWS_PROFILE" --since 5m --format short
    echo "============================================="
fi