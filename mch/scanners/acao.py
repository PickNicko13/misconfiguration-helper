"""ACAO (Access-Control-Allow-Origin) header analysis for the MCH project.

This module provides the `AcaoScanner` class, which probes target endpoints
with various `Origin` headers to detect CORS misconfigurations.
"""

import asyncio
import httpx
from .base import BaseScanner
from mch.utils import setup_logging
from typing import Any
import urllib.parse
import ipaddress
import re
from threading import Lock


class AcaoScanner(BaseScanner):
	"""Asynchronously probes endpoints for CORS vulnerabilities.

	The scanner tests for:
	- Arbitrary origin reflection (allowing any Origin).
	- Broad origin reflection (leaking internal domains).
	- Leaked IPs/Internal hostnames in header values.

	Attributes:
		endpoints_scanned (int): Number of probes sent in this session.
		total_endpoints (int): Calculated total of probes to be sent.
		run_result (Dict): Findings from the last completed scan.

	"""

	def __init__(self, *args, **kwargs):
		"""Initialize the AcaoScanner with default values."""
		super().__init__(*args, **kwargs)
		self.endpoints_scanned = 0
		self.total_endpoints = 0
		self._is_scanning = False
		self.run_result = None
		self._lock = Lock()
		self.logger = setup_logging()

	async def run_async(self) -> dict[str, Any]:
		"""Execute the ACAO scan asynchronously across multiple endpoints and schemas.

		Returns:
			Dict[str, Any]: A list of detected `issues` and their details.

		"""
		results = {'issues': []}
		self.logger.debug(f'Starting AcaoScanner for target: {self.target}')
		target = str(self.target)
		parsed = urllib.parse.urlparse(
			target if target.startswith('http') else f'http://{target}'
		)
		target = parsed.hostname
		if not target:
			self.logger.error(f'Invalid target: {self.target}')
			return results

		endpoints = self.config.get('acao', 'endpoints', ['/'])
		malicious_origins = self.config.get(
			'acao', 'malicious_origins', ['http://malicious-{domain}']
		)
		timeout = self.config.get('acao', 'timeout', 5.0)
		schemes = ['http', 'https']
		arbitrary_origin = 'http://evil.com'
		self.total_endpoints = (
			len(endpoints) * len(schemes) * (len(malicious_origins) + 2)
		)
		self._is_scanning = True

		self.logger.debug(f'Configuration - endpoints: {endpoints}')
		self.logger.debug(f'Configuration - malicious_origins: {malicious_origins}')

		if not isinstance(endpoints, list) or not all(
			isinstance(e, str) for e in endpoints
		):
			self.logger.error(f'Invalid endpoints configuration: {endpoints}')
			return results
		if not isinstance(malicious_origins, list) or not all(
			isinstance(o, str) for o in malicious_origins
		):
			self.logger.error(
				f'Invalid malicious_origins configuration: {malicious_origins}'
			)
			return results

		self.logger.debug(f'Initial state: {self.state.get("acao", {})}')
		if 'acao' not in self.state or not isinstance(self.state['acao'], dict):
			self.logger.debug('Initializing acao state')
			self.state['acao'] = {'issues': []}
		state_issues = self.state['acao'].get('issues', [])
		self.logger.debug(f'State issues for acao: {state_issues}')

		detected_issues = []
		detected_keys = set()

		try:
			async with httpx.AsyncClient(verify=False) as client:
				tasks = []
				for scheme in schemes:
					for endpoint in endpoints:
						target_origin = f'{scheme}://{target}'
						tasks.append(
							(
								scheme,
								endpoint,
								target_origin,
								self.check_endpoint(
									client,
									scheme,
									target,
									endpoint,
									timeout,
									target_origin,
								),
							)
						)
						tasks.append(
							(
								scheme,
								endpoint,
								arbitrary_origin,
								self.check_endpoint(
									client,
									scheme,
									target,
									endpoint,
									timeout,
									arbitrary_origin,
								),
							)
						)
						for origin_template in malicious_origins:
							origin = origin_template.format(domain=target)
							tasks.append(
								(
									scheme,
									endpoint,
									origin,
									self.check_endpoint(
										client,
										scheme,
										target,
										endpoint,
										timeout,
										origin,
									),
								)
							)
				results_list = await asyncio.gather(
					*[t[3] for t in tasks], return_exceptions=True
				)

				for (scheme, endpoint, origin, _), result in zip(tasks, results_list):
					if isinstance(result, Exception):
						self.logger.error(
							f'Error in check_endpoint for {scheme} {endpoint} with origin {origin}: {result}'
						)
						continue
					endpoint_result, acao_values = result
					for acao in acao_values:
						weak_type = None
						detail = acao
						if (urllib.parse.urlparse(acao).hostname or '') == target:
							continue
						if origin == f'{scheme}://{target}':
							if acao not in [
								target,
								f'http://{target}',
								f'https://{target}',
							]:
								is_ip = bool(self.extract_ips(acao))
								weak_type = 'leaked_ip' if is_ip else 'leaked_domain'
						else:
							is_arbitrary = acao == origin
							if is_arbitrary:
								weak_type = 'arbitrary'
								detail = acao
							else:
								parsed_acao = urllib.parse.urlparse(acao)
								acao_host = parsed_acao.hostname or acao

								if acao_host and '.' in acao_host:
									crafted_origin = f'http://evil-{acao_host}'

									_, test_acao_values = await self.check_endpoint(
										client,
										scheme,
										target,
										endpoint,
										timeout,
										crafted_origin,
									)

									if any(
										acao_host in v or crafted_origin in v
										for v in test_acao_values
									):
										weak_type = 'broad-reflection'
										detail = (
											f'{acao} (vulnerable to {crafted_origin})'
										)
									else:
										continue
								else:
									continue

						if weak_type:
							issue = {
								'scheme': scheme,
								'hostname': target,
								'endpoint': endpoint,
								'weak_type': weak_type,
								'detail': detail,
								'status': 'uncategorized',
							}
							issue_key = (scheme, target, endpoint, weak_type, detail)
							if issue_key not in detected_keys:
								detected_keys.add(issue_key)
								handled_issue = self._handle_issue(
									issue, state_issues, endpoint_result, detail, acao
								)
								if handled_issue:
									detected_issues.append(handled_issue)
									if handled_issue['status'] in [
										'uncategorized',
										'will_fix',
									]:
										results['issues'].append(
											{
												'url': endpoint_result,
												'weak_type': weak_type,
												'detail': detail,
												'acao': acao,
											}
										)

			new_issues = []
			for issue in state_issues:
				issue_key = (
					issue['scheme'],
					issue['hostname'],
					issue['endpoint'],
					issue['weak_type'],
					issue['detail'],
				)
				if issue_key in detected_keys:
					if issue['status'] == 'resolved':
						self.logger.error(
							f'Previously resolved acao issue {issue_key} re-detected on {self.target}'
						)
						issue['status'] = 'uncategorized'
					elif issue['status'] in [
						'uncategorized',
						'will_fix',
						'false_positive',
						'wont_fix',
					]:
						self.logger.debug(
							f'Re-detected issue {issue_key} with status {issue["status"]}'
						)
					new_issues.append(issue)
				else:
					if issue['status'] in ['uncategorized', 'will_fix']:
						self.logger.debug(
							f'Marking not re-detected issue {issue_key} as resolved'
						)
						issue['status'] = 'resolved'
						new_issues.append(issue)
					elif issue['status'] == 'wont_fix':
						self.logger.debug(
							f'Marking not re-detected wont-fix issue {issue_key} as resolved'
						)
						issue['status'] = 'resolved'
						new_issues.append(issue)
					elif issue['status'] == 'false_positive':
						self.logger.debug(
							f'Keeping not re-detected false-positive issue {issue_key}'
						)
						new_issues.append(issue)
			self.state['acao']['issues'] = new_issues + detected_issues
			self.logger.debug(f'Updated state: {self.state["acao"]}')
			if not results['issues']:
				self.logger.info(
					f'[cyan]No acao issues found on {self.target} for either HTTP or HTTPS[/cyan]'
				)
		except Exception as e:
			self.logger.error(f'ACAO scan failed: {type(e).__name__} {e}')
		finally:
			self._is_scanning = False
		self.run_result = results
		return results

	async def check_endpoint(
		self,
		client: httpx.AsyncClient,
		scheme: str,
		target: str,
		endpoint: str,
		timeout: float,
		origin: str,
	) -> tuple[str, list[str]]:
		"""Attempt to check an endpoint with specific Origin header.

		Args:
			client: Async HTTPX client instance.
			scheme: Target scheme (http/https).
			target: hostname or IP.
			endpoint: Target absolute or relative path.
			timeout: Connection/Response timeout in seconds.
			origin: The custom `Origin` header to test.

		Returns:
			tuple[str, List[str]]: A tuple of (full_url, list_of_ACAO_values).

		"""
		self.logger.debug(
			f'Checking {scheme} endpoint {endpoint} on {target} with origin {origin}'
		)
		max_retries = 3
		for attempt in range(max_retries):
			try:
				url = urllib.parse.urljoin(f'{scheme}://{target}', endpoint)
				headers = {'Origin': origin}
				self.logger.debug(
					f'Sending HEAD request to {url} with Origin: {origin}'
				)
				r = await client.head(url, headers=headers, timeout=timeout)
				with self._lock:
					self.endpoints_scanned += 1
				acao = r.headers.get('access-control-allow-origin', '')
				acao_values = [v.strip() for v in acao.split() if v.strip()]
				self.logger.debug(
					f'Response status: {r.status_code}, ACAO: {acao_values}'
				)
				return f'{scheme}://{target}{endpoint}', acao_values
			except httpx.ConnectError as e:
				if attempt < max_retries - 1:
					await asyncio.sleep(2**attempt)
					continue
				with self._lock:
					self.endpoints_scanned += 1
				self.logger.debug(f'Connection error checking {scheme} {endpoint}: {e}')
				self.logger.warning(
					f'Connection error for {scheme}://{target}{endpoint}: {type(e).__name__} {e}'
				)
				return f'{scheme}://{target}{endpoint}', []
			except httpx.HTTPError as e:
				if attempt < max_retries - 1:
					await asyncio.sleep(2**attempt)
					continue
				with self._lock:
					self.endpoints_scanned += 1
				self.logger.debug(f'HTTP error checking {scheme} {endpoint}: {e}')
				self.logger.warning(
					f'HTTP error for {scheme}://{target}{endpoint}: {type(e).__name__} {e}'
				)
				return f'{scheme}://{target}{endpoint}', []
			except Exception as e:
				if attempt < max_retries - 1:
					await asyncio.sleep(2**attempt)
					continue
				with self._lock:
					self.endpoints_scanned += 1
				self.logger.error(
					f'Unexpected error checking {scheme} {endpoint}: {type(e).__name__} {e}'
				)
				return f'{scheme}://{target}{endpoint}', []
		with self._lock:
			self.endpoints_scanned += 1
		return f'{scheme}://{target}{endpoint}', []

	def _handle_issue(
		self,
		issue: dict,
		state_issues: list[dict],
		endpoint: str,
		detail: str,
		acao: str,
	) -> dict | None:
		"""Core logic for identifying new issues or re-triggering existing ones.

		Args:
			issue: Proposed new issue dictionary.
			state_issues: Existing issues for this scanner from persistent state.
			endpoint: The probed URL.
			detail: Formatted vulnerability detail.
			acao: The exact value returned in the ACAO header.

		Returns:
			Dict | None: The issue to be added/updated in the state,
				or None if no action is needed.

		"""
		issue_key = (
			issue['scheme'],
			issue['hostname'],
			issue['endpoint'],
			issue['weak_type'],
			issue['detail'],
		)
		for existing_issue in state_issues:
			if (
				existing_issue['scheme'] == issue['scheme']
				and existing_issue['hostname'] == issue['hostname']
				and existing_issue['endpoint'] == issue['endpoint']
				and existing_issue['weak_type'] == issue['weak_type']
				and existing_issue['detail'] == issue['detail']
			):
				status = existing_issue['status']
				if status == 'fixed':
					self.logger.error(
						f'Previously fixed acao issue {issue_key} re-detected on {self.target}'
					)
					existing_issue['status'] = 'uncategorized'
					return existing_issue
				elif status == 'false_positive':
					self.logger.error(
						f'Previously false-positive acao issue {issue_key} re-detected on {self.target}'
					)
					existing_issue['status'] = 'uncategorized'
					return existing_issue
				elif status == 'resolved':
					self.logger.error(
						f'Previously resolved acao issue {issue_key} re-detected on {self.target}'
					)
					existing_issue['status'] = 'uncategorized'
					return existing_issue
				elif status in ['uncategorized', 'will_fix']:
					self.logger.warning(
						f'ACAO issue ({detail}) on {endpoint}: ACAO={acao}'
					)
					return None
				elif status == 'wont_fix':
					self.logger.debug(
						f'Re-detected wont-fix acao issue {issue_key} on {self.target}'
					)
					return None
				return None
		self.logger.warning(f'New acao issue ({detail}) on {endpoint}: ACAO={acao}')
		return issue

	def extract_ips(self, text: str) -> list[str]:
		"""Help to find all valid IPv4 addresses in a string.

		Args:
			text: Any string content.

		Returns:
			List[str]: A list of valid IP addresses found.

		"""
		ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
		matches = re.findall(ip_pattern, text)
		valid_ips = []
		for ip in matches:
			try:
				ipaddress.ip_address(ip)
				valid_ips.append(ip)
			except ValueError:
				self.logger.debug(f'Invalid IP found in text: {ip}')
		return valid_ips

	def get_progress(self) -> str:
		"""Return a formatted progress string for the ACAO scan.

		Returns:
			str: A string like ' 12/400'.

		"""
		with self._lock:
			if self.total_endpoints > 0:
				return f' {self.endpoints_scanned}/{self.total_endpoints}'
		return ''
