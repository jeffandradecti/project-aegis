import os
import csv
import boto3
import hashlib
import pyzipper
import pycdlib
from datetime import datetime

s3 = boto3.client('s3')

# Standardizing variables: Pulling from AWS Environment (Injected by Terraform)
BUCKET_NAME   = os.environ.get("BUCKET_NAME")
SOURCE_FOLDER = os.environ.get("SOURCE_FOLDER", "evidence/malware/")
DEST_FOLDER   = os.environ.get("DEST_FOLDER", "evidence/forensics/")
ZIP_PASSWORD  = os.environ.get("ZIP_PASSWORD", "infected").encode('utf-8')

def hash_file(filepath):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

def lambda_handler(event, context):
    if not BUCKET_NAME:
        return {"statusCode": 500, "body": "CRITICAL: BUCKET_NAME not set in environment."}

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    download_dir = "/tmp/malware_downloads"
    os.makedirs(download_dir, exist_ok=True)

    metadata_rows = [["Filename", "MD5", "SHA1", "SHA256"]]
    downloaded_files = []

    # 1. List and Download files
    paginator = s3.get_paginator('list_objects_v2')
    pages = paginator.paginate(Bucket=BUCKET_NAME, Prefix=SOURCE_FOLDER)

    for page in pages:
        if 'Contents' not in page: continue
        for obj in page['Contents']:
            key = obj['Key']
            if key.endswith('/'): continue

            filename = os.path.basename(key)
            local_path = os.path.join(download_dir, filename)

            s3.download_file(BUCKET_NAME, key, local_path)

            md5_hash, sha1_hash, sha256_hash = hash_file(local_path)
            metadata_rows.append([filename, md5_hash, sha1_hash, sha256_hash])
            downloaded_files.append((filename, local_path))

    if not downloaded_files:
        return {"statusCode": 200, "body": "No files found to process."}

    # 2. Create metadata.csv
    csv_path = "/tmp/metadata.csv"
    with open(csv_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(metadata_rows)

    # 3. Zip with password from environment
    zip_path = "/tmp/malware_samples.zip"
    with pyzipper.AESZipFile(zip_path, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(ZIP_PASSWORD)
        for filename, filepath in downloaded_files:
            zf.write(filepath, arcname=filename)

    # 4. Create ISO
    iso_path = f"/tmp/forensics_{timestamp}.iso"
    iso = pycdlib.PyCdlib()
    iso.new(rock_ridge='1.09')
    iso.add_file(zip_path, '/SAMPLES.ZIP;1', rr_name='malware_samples.zip')
    iso.add_file(csv_path, '/METADATA.CSV;1', rr_name='metadata.csv')
    iso.write(iso_path)
    iso.close()

    # 5. Upload ISO back to S3
    dest_key = f"{DEST_FOLDER}forensics_{timestamp}.iso"
    s3.upload_file(iso_path, BUCKET_NAME, dest_key)

    # Cleanup
    for _, filepath in downloaded_files:
        os.remove(filepath)
    os.remove(zip_path)
    os.remove(csv_path)
    os.remove(iso_path)

    return {
        "statusCode": 200,
        "body": f"Successfully processed forensics package to {dest_key}"
    }