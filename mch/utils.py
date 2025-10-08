import typer
from pathlib import Path
from platformdirs import user_data_dir
import ipaddress
import re
import logging

def validate_target(target: str) -> str:
    if not isinstance(target, str):
        typer.echo(f"Invalid target: {target} (must be a string)", err=True)
        raise typer.Exit(1)
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    if re.match(r"^(https?://)?[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$", target):
        return target
    typer.echo(f"Invalid target: {target} (must be IP or URL)", err=True)
    raise typer.Exit(1)

def setup_logging():
    logger = logging.getLogger("mch")
    if not logger.handlers:  # Prevent duplicate handlers
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        data_dir = Path(user_data_dir("mch"))
        data_dir.mkdir(parents=True, exist_ok=True)
        log_path = data_dir / "mch.log"
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO)
        stream_handler.setFormatter(formatter)
        logger.handlers = [file_handler, stream_handler]
    return logger
