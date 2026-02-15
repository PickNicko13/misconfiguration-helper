"""Utility functions for the MCH (Misconfiguration Scanner) project.

This module provides common functionalities like target validation,
logging setup, and system path resolution.
"""

from typing import Any
import typer
from pathlib import Path
from platformdirs import user_data_dir
import ipaddress
import re
import logging
from rich.logging import RichHandler
from rich.console import Console

console = Console()


def validate_target(target: Any) -> str:
	"""Validate that the provided target is either a valid IP address or a URL.

	Args:
		target: The target string to validate.

	Returns:
		str: The validated target string.

	Raises:
		typer.Exit: If the target is invalid or not a string.

	"""
	if not isinstance(target, str):
		typer.echo(f'Invalid target: {target} (must be a string)', err=True)
		raise typer.Exit(1)
	try:
		ipaddress.ip_address(target)
		return target
	except ValueError:
		pass
	if re.match(r'^(https?://)?[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$', target):
		return target
	typer.echo(f'Invalid target: {target} (must be IP or URL)', err=True)
	raise typer.Exit(1)


def setup_logging() -> logging.Logger:
	"""Set up the logging system for the project.

	Configures:
	- A DEBUG-level file handler at `~/.local/share/mch/mch.log`.
	- An INFO-level `RichHandler` for colorized console output.

	Returns:
		logging.Logger: The configured logger instance named 'mch'.

	"""
	logger = logging.getLogger('mch')
	if not logger.handlers:  # Prevent duplicate handlers
		logger.setLevel(logging.DEBUG)
		formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
		data_dir = Path(user_data_dir('mch'))
		data_dir.mkdir(parents=True, exist_ok=True)
		log_path = data_dir / 'mch.log'
		file_handler = logging.FileHandler(log_path)
		file_handler.setLevel(logging.DEBUG)
		file_handler.setFormatter(formatter)
		# Use RichHandler for console to integrate with Live and enable markup
		console_handler = RichHandler(
			level=logging.INFO,
			show_time=False,
			show_level=True,
			show_path=False,
			markup=True,
		)
		logger.handlers = [file_handler, console_handler]
	return logger
