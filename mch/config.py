"""Configuration management for the MCH project.

This module provides the `ConfigManager` class and default settings for all
scan types (ports, fuzz, and ACAO). It handles loading, saving, and merging
configurations from TOML files and CLI overrides.
"""

import tomli
import tomli_w
from pathlib import Path
from platformdirs import user_config_dir
from typing import Any
from mch.utils import setup_logging

#: Default configuration settings for the project.
DEFAULT_CONFIG = {
	'ports': {
		'range': '1-65535',
		'expected': [80, 443],  # Common expected ports; auto-ack on load
		'timeout': 1.0,
	},
	'fuzz': {
		'wordlist': str(
			Path(__file__).parent / 'wordlists' / 'directory-list-2.3-small.txt'
		),
		'extensions': [],
		'timeout': 5.0,
		'delay': 0.0,
		'concurrency': 50,
	},
	'acao': {
		'endpoints': ['/'],
		'malicious_origins': ['http://malicious-{domain}'],
		'timeout': 5.0,
	},
}


class ConfigManager:
	"""Manages the application configuration by handling TOML persistence.

	This class interacts with the local file system to store and retrieve
	user settings. It also supports runtime merging of CLI-provided overrides.

	Attributes:
		logger: Logger instance for tracking configuration events.
		config_dir (Path): The directory path where the config file is stored.
		config_file (Path): Absolute path to the `config.toml` file.
		config (Dict): The in-memory loaded configuration dictionary.

	"""

	def __init__(self):
		"""Initialize the ConfigManager and load the configuration from disc."""
		self.logger = setup_logging()
		self.config_dir = Path(user_config_dir('mch'))
		self.config_file = self.config_dir / 'config.toml'
		self.config = self.load_config()

	def load_config(self) -> dict[str, Any]:
		"""Load the configuration from the TOML file.

		If the configuration file does not exist, it creates one using the
		`DEFAULT_CONFIG` settings.

		Returns:
			Dict[str, Any]: The configuration data.

		"""
		self.config_dir.mkdir(parents=True, exist_ok=True)
		if not self.config_file.exists():
			self.logger.info(
				f'Config file not found at {self.config_file}. Creating from defaults.'
			)
			self.save_config(DEFAULT_CONFIG)
		try:
			with open(self.config_file, 'rb') as f:
				return tomli.load(f)
		except Exception as e:
			self.logger.error(f'Failed to load config {self.config_file}: {e}')
			return DEFAULT_CONFIG

	def save_config(self, config: dict[str, Any]):
		"""Persist a configuration dictionary to the TOML file.

		Args:
			config: The configuration data to save.

		"""
		try:
			with open(self.config_file, 'wb') as f:
				tomli_w.dump(config, f)
		except Exception as e:
			self.logger.error(f'Failed to save config {self.config_file}: {e}')

	def get(self, section: str, key: str, default: Any = None) -> Any:
		"""Retrieve a specific configuration value from a section.

		Args:
			section: The top-level settings category (e.g., 'ports').
			key: The specific setting name within that section.
			default: A fallback value if the key/section is missing.

		Returns:
			Any: The configuration value or the default.

		"""
		return self.config.get(section, {}).get(key, default)

	def merge_overrides(self, overrides: dict[str, Any]):
		"""Merge runtime configuration overrides into the main settings.

		Args:
			overrides: A dictionary of nested settings to merge.

		"""
		for section, values in overrides.items():
			if section in self.config:
				self.config[section].update(values)
			else:
				self.config[section] = values
