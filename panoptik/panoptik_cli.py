import argparse
import json
import os
import sys
from pathlib import Path

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__))))
from src.engine import AnalysisEngine
from src.services import MalapiService, S3Service
from src.analyzers.basic import BasicInfoAnalyzer, StringAnalyzer
from src.analyzers.pe_analyzer import PEAnalyzer
from src.analyzers.capa_analyzer import CapaAnalyzer


def main():
    parser = argparse.ArgumentParser(description="Panoptik: Malware Triage Orchestrator")
    parser.add_argument("target", help="Path to local file OR s3://bucket/prefix")
    parser.add_argument("-o", "--output", help="Custom results directory (defaults to ./results)")
    parser.add_argument("--cleanup", action="store_true", help="Delete downloaded S3 samples after analysis")
    parser.add_argument("--max-size", type=int, default=5, help="Maximum file size in MB to process")
    args = parser.parse_args()
    malapi = MalapiService("malapi.json")
    s3 = S3Service()
    engine = AnalysisEngine()
    engine.register_analyzer(BasicInfoAnalyzer())
    engine.register_analyzer(StringAnalyzer())
    engine.register_analyzer(PEAnalyzer(malapi_service=malapi))
    engine.register_analyzer(CapaAnalyzer())
    results_dir = Path(args.output) if args.output else Path(os.getcwd()) / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    temp_dir = Path("/tmp/panoptik_downloads")
    temp_dir.mkdir(parents=True, exist_ok=True)
    targets = []
    if args.target.startswith("s3://"):
        print(f"[*] Processing S3 target: {args.target}")
        for bucket, key, size in s3.list_new_samples(args.target, results_dir, args.max_size):
            print(f"[+] Found new sample: {key} ({size} bytes)")
            local_file = temp_dir / Path(key).name
            s3.download_file(bucket, key, local_file)
            targets.append(local_file)
    else:
        local_path = Path(args.target)
        if local_path.exists():
            targets.append(local_path)
        else:
            print(f"[-] Error: File not found: {local_path}")
            sys.exit(1)
    processed_count = 0
    for file_path in targets:
        try:
            report = engine.process(str(file_path))
            report_filename = f"{file_path.name}_full_report.json"
            report_path = results_dir / report_filename
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=4, default=str)
            print(f"[!] Report saved: {report_path}")
            processed_count += 1
            if args.cleanup and args.target.startswith("s3://"):
                file_path.unlink()
        except Exception as e:
            print(f"[-] Failed analyzing {file_path.name}: {e}")
    print(f"\n[*] Panoptik finished. Processed {processed_count} files.")


if __name__ == "__main__":
    main()
