"""State management functionality for the MCH project.

This module provides the `StateManager` class which handles the persistent
storage of scan results across multiple runs on a per-host basis.
"""

import json
import os
from pathlib import Path
from platformdirs import user_data_dir
from typing import Any
from mch.utils import setup_logging
import hashlib


class StateManager:
	"""Handles the loading and saving of host-specific scan results.

	States are stored as JSON files within the user's data directory. Each
	host's data is uniquely identified by an MD5 hash of its hostname/IP.

	Attributes:
		logger: Logger instance for tracking state operations.
		state_dir (Path): The directory path where state files are persisted.

	"""

	def __init__(self):
		"""Initialize the StateManager and ensure the state directory exists."""
		self.logger = setup_logging()

		self.state_dir = Path(user_data_dir('mch')) / 'targets'
		os.makedirs(self.state_dir, exist_ok=True)

	def _get_state_file(self, host: str) -> str:
		"""Generate a unique absolute path for a host's state file.

		Args:
			host: Target hostname or IP address.

		Returns:
			str: Absolute path to the host-specific JSON state file.

		"""
		# Normalize host to avoid file system issues
		safe_host = hashlib.md5(host.encode()).hexdigest()
		return os.path.join(self.state_dir, f'{safe_host}.json')

	def load_state(self, host: str) -> dict[str, Any]:
		"""Load the existing state for a host or return the default empty state.

		Args:
			host: Target hostname or IP address.

		Returns:
			Dict[str, Any]: The current state of the target, including
				ports, fuzz issues, and ACAO results.

		"""
		state_file = self._get_state_file(host)
		default_state = {
			'ports': {'current_open': [], 'acknowledged': []},
			'fuzz': {
				'issues': [],
				'will_fix': [],
				'false_positive': [],
				'wont_fix': [],
			},
			'acao': {'issues': []},
		}
		try:
			if os.path.exists(state_file):
				with open(state_file) as f:
					state = json.load(f)
					default_state.update(state)
					self.logger.debug(f'Loaded state for {host}: {default_state}')
			else:
				self.logger.debug(
					f'No state file found for {host}, using default state'
				)
		except Exception as e:
			self.logger.error(f'Failed to load state for {host}: {e}')
		return default_state

	def save_state(self, host: str, state: dict[str, Any]):
		"""Persist the current state of a host to its corresponding JSON file.

		Args:
			host: Target hostname or IP address.
			state: The dictionary representing the state to be saved.

		"""
		state_file = self._get_state_file(host)
		try:
			with open(state_file, 'w') as f:
				json.dump(state, f, indent='\t')
			self.logger.debug(f'Saved state for {host} to {state_file}')
		except Exception as e:
			self.logger.error(f'Failed to save state for {host}: {e}')
