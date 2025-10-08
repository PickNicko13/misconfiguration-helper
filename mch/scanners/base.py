from abc import ABC, abstractmethod
from mch.config import ConfigManager
from mch.state import StateManager
from mch.utils import setup_logging
from rich.console import Console
from typing import Dict, Any

console = Console()

class BaseScanner(ABC):
    def __init__(self, target: str, config: ConfigManager, state_mgr: StateManager, warn_html_errors: bool = False):
        self.target = target
        self.config = config
        self.state_mgr = state_mgr
        self.state = self.state_mgr.load_state(target)
        self.warn_html_errors = warn_html_errors
        self.logger = setup_logging()

    @abstractmethod
    def run(self) -> Dict[str, Any]:
        """Perform scan, update state, return results/warnings."""
        pass

    def save(self):
        self.state_mgr.save_state(self.target, self.state)
