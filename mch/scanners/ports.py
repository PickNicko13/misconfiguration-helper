import asyncio
import socket
from .base import BaseScanner
from mch.utils import setup_logging
from typing import Dict, Any
import re
from threading import Lock
from rich import print as rich_print

class PortsScanner(BaseScanner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ports_scanned = 0
        self.total_ports = 0
        self._is_scanning = False
        self.run_result = None
        self._lock = Lock()
        self.logger = setup_logging()

    def is_scanning(self) -> bool:
        with self._lock:
            return self._is_scanning

    async def scan_port(self, target: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> bool:
        """Attempt to connect to a single port asynchronously."""
        async with semaphore:
            try:
                conn = asyncio.open_connection(target, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                writer.close()
                await writer.wait_closed()
                with self._lock:
                    self.ports_scanned += 1
                return True
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                with self._lock:
                    self.ports_scanned += 1
                return False

    async def run(self) -> Dict[str, Any]:
        results = {"new_ports": []}
        self.logger.debug(f"Starting port scan on {self.target}")
        target = str(self.target)
        if not isinstance(target, str):
            self.logger.error(f"Invalid target type: {type(self.target)} (value: {self.target})")
            rich_print(f"[red]Invalid target: {self.target}[/red]")
            return results
        scan_range = self.config.get("ports", "range", "1-65535")
        if not isinstance(scan_range, str) or not re.match(r"^\d+-\d+$", scan_range):
            self.logger.error(f"Invalid port range: {scan_range} (must be string like '1-65535')")
            rich_print(f"[red]Invalid port range: {scan_range}[/red]")
            return results
        try:
            start, end = map(int, scan_range.split("-"))
            if not (1 <= start <= end <= 65535):
                raise ValueError("Ports out of valid range (1-65535)")
            self.total_ports = end - start + 1
        except ValueError as e:
            self.logger.error(f"Invalid port range format: {scan_range} ({e})")
            rich_print(f"[red]Invalid port range: {scan_range}[/red]")
            return results
        with self._lock:
            self._is_scanning = True
        try:
            semaphore = asyncio.Semaphore(100)
            open_ports = []
            acknowledged = self.state["ports"].get("acknowledged", [])
            tasks = [self.scan_port(target, port, 1.0, semaphore) for port in range(start, end + 1)]
            results_chunk = await asyncio.gather(*tasks, return_exceptions=True)
            for port, result in zip(range(start, end + 1), results_chunk):
                if isinstance(result, Exception):
                    self.logger.debug(f"Error scanning port {port} on {target}: {result}")
                    continue
                if result is True:
                    if port in acknowledged:
                        self.logger.debug(f"Port {port} on {target} acknowledged")
                    else:
                        rich_print(f"[yellow]Warning: New open port on {target}: {port}[/yellow]")
                        open_ports.append(port)
            self.state["ports"]["current_open"] = sorted(list(set(self.state["ports"].get("current_open", []) + open_ports)))
            new_ports = [p for p in open_ports if p not in acknowledged]
            if not new_ports:
                rich_print(f"[cyan]No new open ports on {self.target}[/cyan]")
            results["new_ports"] = new_ports
        except Exception as e:
            self.logger.error(f"Port scan failed: {type(e).__name__} {e}")
            rich_print(f"[red]Port scan failed: {type(e).__name__} {e}[/red]")
        finally:
            with self._lock:
                self._is_scanning = False
            self.save()
        self.run_result = results
        return results

    def get_progress(self) -> str:
        with self._lock:
            if self.total_ports > 0:
                return f" {self.ports_scanned}/{self.total_ports}"
            return ""
