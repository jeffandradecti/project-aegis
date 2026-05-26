#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Dynamically locate the project root
TARGET_DIR="$SCRIPT_DIR"
while [[ "$TARGET_DIR" != "/" && ! -f "$TARGET_DIR/.env" ]]; do
    TARGET_DIR="$(dirname "$TARGET_DIR")"
done
PROJECT_ROOT="$TARGET_DIR"

TERRAFORM_DIR="$PROJECT_ROOT/terraform"
PANOPTIK_SRC="$PROJECT_ROOT/panoptik/src"
SOURCE_SCRIPT="$PANOPTIK_SRC/lambda_function.py"
PACKAGE_DIR="$SCRIPT_DIR/lambda_package"
ZIP_PATH="$TERRAFORM_DIR/forensics_lambda.zip"

echo "Building Panoptik forensics Lambda package (Linux-Targeted)..."

rm -rf "$PACKAGE_DIR"
rm -f "$ZIP_PATH"
mkdir -p "$PACKAGE_DIR"

echo "Downloading Linux x86_64 binaries for pyzipper and pycdlib..."
pip install \
    --platform manylinux2014_x86_64 \
    --target "$PACKAGE_DIR" \
    --implementation cp \
    --python-version 3.10 \
    --only-binary=:all: \
    pyzipper pycdlib boto3

echo "Copying python handler..."
cp "$SOURCE_SCRIPT" "$PACKAGE_DIR/"

echo "Zipping deployment package..."
pushd "$PACKAGE_DIR" > /dev/null || exit
zip -rq "$ZIP_PATH" ./*
popd > /dev/null || exit

echo "Cleaning up temp files..."
rm -rf "$PACKAGE_DIR"

echo "[+] Success! The ZIP now contains Linux .so binaries."