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


def setup_logging():
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
