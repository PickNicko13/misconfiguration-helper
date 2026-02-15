"""Port scanning functionality for the MCH project.

This module provides the `PortScanner` class, which asynchronously scans a
range of TCP ports on a target host and identifies open ports.
"""

import asyncio
from .base import BaseScanner
from mch.utils import setup_logging
from typing import Any
import re
from threading import Lock


class PortScanner(BaseScanner):
	"""Asynchronously scans TCP ports on a target host.

	This scanner identifies open ports within a specified range and compares
	them against the set of already acknowledged ports to report new findings.

	Attributes:
		ports_scanned (int): The number of ports scanned in the current session.
		total_ports (int): The total number of ports to be scanned.
		run_result (Dict): Stores the results of the last completed scan.

	"""

	def __init__(self, *args, **kwargs):
		"""Initialize the PortScanner with default values."""
		super().__init__(*args, **kwargs)
		self.ports_scanned = 0
		self.total_ports = 0
		self._is_scanning = False
		self.run_result = None
		self._lock = Lock()
		self.logger = setup_logging()

	async def run_async(self) -> dict[str, Any]:
		"""Execute the port scan asynchronously.

		Returns:
			Dict[str, Any]: A dictionary containing a list of `new_ports` found.

		"""
		results = {'new_ports': []}
		self.logger.debug(f'Starting port scan on {self.target}')
		target = str(self.target)
		if not isinstance(target, str):
			self.logger.error(
				f'Invalid target type: {type(self.target)} (value: {self.target})'
			)
			return results
		scan_range = self.config.get('ports', 'range', '1-65535')
		timeout = self.config.get('ports', 'timeout', 1.0)
		if not isinstance(scan_range, str) or not re.match(r'^\d+-\d+$', scan_range):
			self.logger.error(
				f"Invalid port range: {scan_range} (must be string like '1-65535')"
			)
			return results
		try:
			start, end = map(int, scan_range.split('-'))
			if not (1 <= start <= end <= 65535):
				raise ValueError('Ports out of valid range (1-65535)')
			self.total_ports = end - start + 1
		except ValueError as e:
			self.logger.error(f'Invalid port range format: {scan_range} ({e})')
			return results
		with self._lock:
			self._is_scanning = True
		try:
			semaphore = asyncio.Semaphore(100)
			all_open_ports = []
			acknowledged = self.state['ports'].get('acknowledged', [])
			tasks = [
				self.scan_port(target, port, timeout, semaphore)
				for port in range(start, end + 1)
			]
			results_chunk = await asyncio.gather(*tasks, return_exceptions=True)
			for port, result in zip(range(start, end + 1), results_chunk):
				if isinstance(result, Exception):
					self.logger.debug(
						f'Error scanning port {port} on {target}: {result}'
					)
					continue
				if result is True:
					all_open_ports.append(port)
					if port not in acknowledged:
						self.logger.warning(f'New open port on {target}: {port}')
			self.state['ports']['current_open'] = sorted(all_open_ports)
			new_ports = [p for p in all_open_ports if p not in acknowledged]
			if not new_ports:
				self.logger.info(f'[cyan]No new open ports on {self.target}[/cyan]')
			results['new_ports'] = new_ports
		except Exception as e:
			self.logger.error(f'Port scan failed: {type(e).__name__} {e}')
		finally:
			with self._lock:
				self._is_scanning = False
		self.run_result = results
		return results

	async def scan_port(
		self, target: str, port: int, timeout: float, semaphore: asyncio.Semaphore
	) -> bool:
		"""Attempt to open a connection to a specific port.

		Args:
			target: The hostname or IP to scan.
			port: The port number to test.
			timeout: Maximum time to wait for a connection in seconds.
			semaphore: To control the concurrency of the scan.

		Returns:
			bool: True if the port is open, False otherwise.

		"""
		async with semaphore:
			max_retries = 3
			for attempt in range(max_retries):
				try:
					conn = asyncio.open_connection(target, port)
					reader, writer = await asyncio.wait_for(conn, timeout=timeout)
					writer.close()
					await writer.wait_closed()
					with self._lock:
						self.ports_scanned += 1
					return True
				except (TimeoutError, ConnectionRefusedError, OSError) as e:
					if attempt < max_retries - 1:
						await asyncio.sleep(0.1 * (2**attempt))
						continue
					with self._lock:
						self.ports_scanned += 1
					self.logger.debug(
						f'Connection refused/timeout on port {port} of {target}: {type(e).__name__}'
					)
					# No per-port print (high volume); summarize if needed post-scan
					return False
				except Exception as e:
					if attempt < max_retries - 1:
						await asyncio.sleep(0.1 * (2**attempt))
						continue
					with self._lock:
						self.ports_scanned += 1
					self.logger.debug(f'Unexpected error on port {port}: {e}')
					self.logger.error(
						f'Unexpected error scanning port {port} on {target}: {type(e).__name__} {e}'
					)
					return False
			with self._lock:
				self.ports_scanned += 1
			return False

	def get_progress(self) -> str:
		"""Return a formatted progress string for the port scan.

		Returns:
			str: A string like ' 125/65535'.

		"""
		with self._lock:
			if self.total_ports > 0:
				return f' {self.ports_scanned}/{self.total_ports}'
		return ''
