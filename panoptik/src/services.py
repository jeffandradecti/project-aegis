import io
import json
import os
import shutil
import stat
import sys
import urllib.request
import zipfile
from pathlib import Path

import boto3


class MalapiService:
    """Handles the external API database."""

    def __init__(self, db_filename="malapi.json"):
        base_dir = Path(__file__).resolve().parent.parent
        full_path = base_dir / "data" / db_filename
        self.db = {}
        if full_path.exists():
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    self.db = json.load(f)
            except Exception as e:
                print(f"[!] Failed to load malapi.json: {e}", file=sys.stderr)
        else:
            docker_path = Path("/app/panoptik/data/malapi.json")
            if docker_path.exists():
                with open(docker_path, "r", encoding="utf-8") as f:
                    self.db = json.load(f)
            else:
                print(f"[!] Warning: malapi.json not found at {full_path}", file=sys.stderr)

    def lookup(self, func_name):
        for key in self.db:
            if key.lower() == func_name.lower():
                return self.db[key]
        return None


class CapaSetupService:
    """Manages the installation of Capa and its rules."""
    GITHUB_API = "https://api.github.com/repos/mandiant/capa/releases/latest"
    RULES_URL = "https://github.com/mandiant/capa-rules/archive/refs/heads/master.zip"

    def __init__(self, tools_dir="/usr/local/etc/capabilities_extraction"):
        self.base_dir = Path(tools_dir)
        self.capa_bin = self.base_dir / "capa"
        self.rules_dir = self.base_dir / "capa-rules"
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def ensure_tooling(self):
        if not self.capa_bin.exists():
            self._download_capa()
        if not self.rules_dir.exists():
            self._download_rules()
        return self.capa_bin, self.rules_dir

    def _download_capa(self):
        print("[*] Downloading Capa binary...")
        try:
            with urllib.request.urlopen(self.GITHUB_API) as response:
                data = json.load(response)
            asset_url = next((a["browser_download_url"] for a in data["assets"]
                              if a["name"].lower().endswith("linux.zip")), None)
            if not asset_url: raise RuntimeError("No Linux release found for Capa.")
            with urllib.request.urlopen(asset_url) as response:
                with zipfile.ZipFile(io.BytesIO(response.read())) as z:
                    for name in z.namelist():
                        if name == "capa":
                            z.extract(name, self.base_dir)
                            st = os.stat(self.capa_bin)
                            os.chmod(self.capa_bin, st.st_mode | stat.S_IEXEC)
        except Exception as e:
            print(f"[!] Capa download failed: {e}", file=sys.stderr)

    def _download_rules(self):
        print("[*] Downloading Capa rules...")
        try:
            with urllib.request.urlopen(self.RULES_URL) as response:
                with zipfile.ZipFile(io.BytesIO(response.read())) as z:
                    z.extractall(self.base_dir)
                    extracted_root = self.base_dir / z.namelist()[0].split('/')[0]
                    if self.rules_dir.exists(): shutil.rmtree(self.rules_dir)
                    extracted_root.rename(self.rules_dir)
        except Exception as e:
            print(f"[!] Capa Rules download failed: {e}", file=sys.stderr)


class S3Service:
    """Handles interaction with AWS S3."""

    def __init__(self, region="us-east-1"):
        self.s3 = boto3.client("s3", region_name=region)

    def list_new_samples(self, s3_path: str, results_dir: Path, max_size_mb=5):
        if "s3://" in s3_path:
            s3_path = s3_path.replace("s3://", "")
        if "/" in s3_path:
            bucket, prefix = s3_path.split("/", 1)
        else:
            bucket, prefix = s3_path, ""
        max_bytes = max_size_mb * 1024 * 1024
        existing_files = {f.name.replace("_full_report.json", "") for f in results_dir.glob("*_full_report.json")}
        print(f"[*] Checking S3 delta against {len(existing_files)} local reports...")
        paginator = self.s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                size = obj["Size"]
                if key.endswith("/"): continue
                fname = key.split("/")[-1]
                if size > max_bytes:
                    print(f"[!] Skipping {key} (Size {size} > {max_bytes} bytes)")
                    continue
                if fname in existing_files:
                    continue
                yield bucket, key, size

    def download_file(self, bucket, key, dest_path):
        self.s3.download_file(bucket, key, str(dest_path))
