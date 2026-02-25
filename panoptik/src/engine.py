import sys
from typing import List

from .interfaces import AnalyzerStrategy
from .models import FileArtifact, AnalysisReport


class AnalysisEngine:
    def __init__(self):
        self.analyzers: List[AnalyzerStrategy] = []

    def register_analyzer(self, analyzer: AnalyzerStrategy):
        self.analyzers.append(analyzer)

    def process(self, file_path: str) -> AnalysisReport:
        artifact = FileArtifact.from_path(file_path)
        report = AnalysisReport()
        print(f"[*] Starting Analysis Pipeline for: {artifact.name}", file=sys.stderr)
        for analyzer in self.analyzers:
            try:
                analyzer.analyze(artifact, report)
            except Exception as e:
                error_msg = f"Analyzer {type(analyzer).__name__} failed: {str(e)}"
                print(f"[!] {error_msg}", file=sys.stderr)
        return report
