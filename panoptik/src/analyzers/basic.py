import hashlib
import re

import magic

from ..interfaces import AnalyzerStrategy
from ..models import FileArtifact, AnalysisReport


class BasicInfoAnalyzer(AnalyzerStrategy):
    def analyze(self, artifact: FileArtifact, report: AnalysisReport):
        report.file_info["name"] = artifact.name
        report.file_info["size"] = artifact.size
        report.hashes["md5"] = hashlib.md5(artifact.data).hexdigest()
        report.hashes["sha256"] = hashlib.sha256(artifact.data).hexdigest()
        try:
            report.file_info["type"] = magic.from_buffer(artifact.data)
        except Exception:
            report.file_info["type"] = "Unknown"
        if re.search(r'\.(pdf|docx|xlsx|txt|jpg|png)\.exe$', artifact.name.lower()):
            report.add_risk(4, "Double Extension Detected")


class StringAnalyzer(AnalyzerStrategy):
    def analyze(self, artifact: FileArtifact, report: AnalysisReport):
        ascii_strings = re.findall(b"[ -~]{8,}", artifact.data)
        wide_strings = re.findall(b"(?:[\x20-\x7E]\x00){8,}", artifact.data)
        decoded = []
        for s in ascii_strings:
            decoded.append(s.decode("utf-8", errors="ignore"))
        for s in wide_strings:
            decoded.append(s.decode("utf-16le", errors="ignore"))
        clean = [s for s in set(decoded) if not self._is_gibberish(s)]
        clean.sort(key=len, reverse=True)
        report.strings = clean[:20]

    def _is_gibberish(self, s):
        if len(s) > 6:
            vowels = len(re.findall(r'[aeiouAEIOU]', s))
            if (vowels / len(s)) < 0.15: return True
        return False
