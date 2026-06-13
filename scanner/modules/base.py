"""Base module interface for the scanner plugin architecture."""
from abc import ABC, abstractmethod


class BaseModule(ABC):
    """Abstract base for all scanner modules.

    Subclasses must define: name, description, requires_url, run().
    """

    name: str = ""
    description: str = ""
    requires_url: bool = False

    @abstractmethod
    def run(self, target: str, request_handler, output) -> dict:
        """Execute the module and return findings.

        Args:
            target: Domain name or full URL (see requires_url)
            request_handler: RequestHandler instance
            output: Output instance

        Returns:
            {"module": self.name, "findings": [<dict>, ...]}
        """
        ...
