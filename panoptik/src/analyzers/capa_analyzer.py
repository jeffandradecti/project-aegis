import json
import subprocess

from ..interfaces import AnalyzerStrategy
from ..models import FileArtifact, AnalysisReport
from ..services import CapaSetupService


class CapaAnalyzer(AnalyzerStrategy):
    def __init__(self):
        self.setup = CapaSetupService()
        self.capa_bin, self.rules_path = self.setup.ensure_tooling()

    def analyze(self, artifact: FileArtifact, report: AnalysisReport):
        print(f"[*] Running Capa on {artifact.name}...")
        command = [
            str(self.capa_bin),
            artifact.path,
            "-r", str(self.rules_path),
            "-vv", "-j"
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            if result.stdout.strip():
                try:
                    capa_data = json.loads(result.stdout)
                    report.structure_info["capabilities"] = capa_data
                    if "attacks" in capa_data:
                        for attack in capa_data["attacks"]:
                            tactic = attack.get('tactic', 'Unknown')
                            report.add_risk(2, f"MITRE Tactic: {tactic}")
                except json.JSONDecodeError:
                    report.structure_info["capa_error"] = "JSON Decode Failed"
                    report.structure_info["capa_raw"] = result.stdout[:500]
            else:
                report.structure_info["capa_error"] = result.stderr
        except Exception as e:
            report.structure_info["capa_exception"] = str(e)
