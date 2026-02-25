from abc import ABC, abstractmethod

from .models import FileArtifact, AnalysisReport


class AnalyzerStrategy(ABC):
    """Interface that all analysis modules must implement."""

    @abstractmethod
    def analyze(self, artifact: FileArtifact, report: AnalysisReport):
        """
        Analyze the artifact and update the report in-place.
        """
        pass
