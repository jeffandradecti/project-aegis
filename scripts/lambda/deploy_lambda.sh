#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Dynamically locate the project root
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
    echo "CRITICAL: .env file missing at $ENV_FILE"
    exit 1
fi

unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN

TERRAFORM_DIR="$PROJECT_ROOT/terraform"
FETCH_SCRIPT="$PROJECT_ROOT/scripts/artifacts/fetch_forensics.sh"
SOURCE_SCRIPT="$PROJECT_ROOT/panoptik/src/lambda_function.py"

CURRENT_IDENTITY=$(aws sts get-caller-identity --query "Arn" --output text)
echo "Current Identity: $CURRENT_IDENTITY"
if [[ "$CURRENT_IDENTITY" == *"capa-analysis"* ]]; then
    echo "CRITICAL: Still stuck on capa-analysis! Close terminal and restart." >&2
    exit 1
fi

# Look for Terraform in PATH first, fallback to searching the project root if it's a local .exe
TERRAFORM_EXE=$(command -v terraform || command -v terraform.exe)
if [ -z "$TERRAFORM_EXE" ]; then
    TERRAFORM_EXE=$(find "$PROJECT_ROOT" -maxdepth 3 -type f \( -name "terraform" -o -name "terraform.exe" \) | head -n 1)
fi

if [ -z "$TERRAFORM_EXE" ] || [ ! -f "$SOURCE_SCRIPT" ]; then
    echo "CRITICAL: Missing Terraform executable or lambda_function.py at $SOURCE_SCRIPT" >&2
    exit 1
fi

cd "$TERRAFORM_DIR" || exit
"$TERRAFORM_EXE" init > /dev/null

"$TERRAFORM_EXE" import -var="forensics_bucket_name=$BUCKET_NAME" aws_iam_role.lambda_forensics_role lambda_forensics_execution_role 2>/dev/null || true
"$TERRAFORM_EXE" import -var="forensics_bucket_name=$BUCKET_NAME" aws_iam_policy.lambda_s3_policy "arn:aws:iam::${ACCOUNT_ID}:policy/lambda_forensics_s3_policy" 2>/dev/null || true
"$TERRAFORM_EXE" import -var="forensics_bucket_name=$BUCKET_NAME" aws_lambda_function.forensics_processor MalwareForensicsProcessor 2>/dev/null || true

# --- BUILD PACKAGE ---
cd "$SCRIPT_DIR" || exit
PACKAGE_DIR="$SCRIPT_DIR/lambda_package"
ZIP_PATH="$TERRAFORM_DIR/forensics_lambda.zip"

rm -rf "$PACKAGE_DIR"
rm -f "$ZIP_PATH"
mkdir -p "$PACKAGE_DIR"

cp "$SOURCE_SCRIPT" "$PACKAGE_DIR/lambda_function.py"

pip install \
    --platform manylinux2014_x86_64 \
    --target "$PACKAGE_DIR" \
    --implementation cp \
    --python-version 3.10 \
    --only-binary=:all: \
    pyzipper pycdlib boto3

pushd "$PACKAGE_DIR" > /dev/null || exit
zip -rq "$ZIP_PATH" ./*
popd > /dev/null || exit
rm -rf "$PACKAGE_DIR"

# --- DEPLOY INFRASTRUCTURE ---
cd "$TERRAFORM_DIR" || exit
"$TERRAFORM_EXE" apply -var="forensics_bucket_name=$BUCKET_NAME" -auto-approve

# --- FETCH RESULTS ---
cd "$SCRIPT_DIR" || exit
if [ -f "$FETCH_SCRIPT" ]; then
    bash "$FETCH_SCRIPT"
else
    echo "[-] Fetch script not found at $FETCH_SCRIPT"
fi