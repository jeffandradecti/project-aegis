import pefile

from ..interfaces import AnalyzerStrategy
from ..models import FileArtifact, AnalysisReport
from ..services import MalapiService


class PEAnalyzer(AnalyzerStrategy):
    def __init__(self, malapi_service: MalapiService):
        self.malapi = malapi_service
        self.known_bad_imphashes = {
            "7a8b9c": "Generic Downloader",
        }

    def analyze(self, artifact: FileArtifact, report: AnalysisReport):
        if not artifact.data.startswith(b'MZ'):
            return
        try:
            pe = pefile.PE(data=artifact.data)
            report.structure_info["compile_time"] = pe.FILE_HEADER.TimeDateStamp
            imphash = pe.get_imphash()
            report.structure_info["imphash"] = imphash
            if imphash in self.known_bad_imphashes:
                report.add_risk(5, f"Known Malicious Imphash: {self.known_bad_imphashes[imphash]}")
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if not imp.name: continue
                        func_name = imp.name.decode('utf-8', 'ignore')
                        api_info = self.malapi.lookup(func_name)
                        if api_info:
                            report.add_risk(1, f"Suspicious API: {func_name}")
            max_entropy = 0
            for section in pe.sections:
                e = section.get_entropy()
                if e > max_entropy: max_entropy = e
            report.structure_info["max_entropy"] = round(max_entropy, 2)
            if max_entropy > 7.4:
                report.add_risk(3, "High Entropy Section (Likely Packed)")
        except pefile.PEFormatError:
            pass
