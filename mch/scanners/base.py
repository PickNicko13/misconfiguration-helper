"""Base scanner interface for the MCH project.

This module defines the abstract base class `BaseScanner` that all logic-specific
scanners (ports, fuzz, ACAO) must inherit from to ensure a consistent interface.
"""

from abc import ABC, abstractmethod
from mch.config import ConfigManager
from mch.state import StateManager
from mch.utils import setup_logging
from rich.console import Console
from typing import Any

#: Global rich console instance for output consistency.
console = Console()


class BaseScanner(ABC):
	"""Abstract base class for all MCH scanners.

	Provides common initialization for target-specific configuration,
	state management, and logging.

	Attributes:
		target (str): The hostname or IP to be scanned.
		config (ConfigManager): Project-wide configuration manager.
		state_mgr (StateManager): Shared state manager for persistence.
		state (Dict): Host-specific current state loaded from the state manager.
		warn_html_errors (bool): Whether to report HTML parsing issues.
		logger: Configured logger for the scanner.

	"""

	def __init__(
		self,
		target: str,
		config: ConfigManager,
		state_mgr: StateManager,
		warn_html_errors: bool = False,
	):
		"""Initialize the scanner with its required dependencies.

		Args:
			target: The search target.
			config: Configuration manager instance.
			state_mgr: State manager instance.
			warn_html_errors: Toggle for HTML error reporting.

		"""
		self.target = target
		self.config = config
		self.state_mgr = state_mgr
		self.state = self.state_mgr.load_state(target)
		self.warn_html_errors = warn_html_errors
		self.logger = setup_logging()

	@abstractmethod
	async def run_async(self) -> dict[str, Any]:
		"""Perform the scan logic asynchronously.

		Each subclass must implement this method to perform its specific
		probing and analysis.

		Returns:
			Dict[str, Any]: A dictionary containing scan findings and metadata.

		"""
		pass

	def save(self):
		"""Persist the scanner's current internal state to disc."""
		self.state_mgr.save_state(self.target, self.state)
