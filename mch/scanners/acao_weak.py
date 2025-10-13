import asyncio
import httpx
from .base import BaseScanner
from mch.utils import setup_logging
from typing import Dict, Any, List
import urllib.parse
import ipaddress
import re
from threading import Lock

class AcaoWeakScanner(BaseScanner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.endpoints_scanned = 0
        self.total_endpoints = 0
        self._is_scanning = False
        self.run_result = None
        self._lock = Lock()
        self.logger = setup_logging()

    async def run_async(self) -> Dict[str, Any]:
        results = {"issues": []}
        self.logger.debug(f"Starting AcaoWeakScanner for target: {self.target}")
        target = str(self.target)
        parsed = urllib.parse.urlparse(target if target.startswith("http") else f"http://{target}")
        target = parsed.hostname
        if not target:
            self.logger.error(f"Invalid target: {self.target}")
            return results

        endpoints = self.config.get("acao-weak", "endpoints", ["/"])
        malicious_origins = self.config.get("acao-weak", "malicious_origins", ["http://malicious-{domain}"])
        timeout = self.config.get("acao-weak", "timeout", 5.0)
        schemes = ["http", "https"]
        arbitrary_origin = "http://evil.com"
        # Total endpoints: (malicious_origins + arbitrary origin + target origin) per endpoint per scheme
        self.total_endpoints = len(endpoints) * len(schemes) * (len(malicious_origins) + 2)
        self._is_scanning = True

        self.logger.debug(f"Configuration - endpoints: {endpoints}")
        self.logger.debug(f"Configuration - malicious_origins: {malicious_origins}")

        if not isinstance(endpoints, list) or not all(isinstance(e, str) for e in endpoints):
            self.logger.error(f"Invalid endpoints configuration: {endpoints}")
            return results
        if not isinstance(malicious_origins, list) or not all(isinstance(o, str) for o in malicious_origins):
            self.logger.error(f"Invalid malicious_origins configuration: {malicious_origins}")
            return results

        self.logger.debug(f"Initial state: {self.state.get('acao-weak', {})}")
        if "acao-weak" not in self.state or not isinstance(self.state["acao-weak"], dict):
            self.logger.debug("Initializing acao-weak state")
            self.state["acao-weak"] = {"issues": []}
        state_issues = self.state["acao-weak"].get("issues", [])
        self.logger.debug(f"State issues for acao-weak: {state_issues}")

        detected_issues = []
        detected_keys = set()

        try:
            async with httpx.AsyncClient(verify=False) as client:
                tasks = []
                for scheme in schemes:
                    for endpoint in endpoints:
                        # Test target origin
                        target_origin = f"{scheme}://{target}"
                        tasks.append((scheme, endpoint, target_origin, self.check_endpoint(client, scheme, target, endpoint, timeout, target_origin)))
                        # Test arbitrary origin
                        tasks.append((scheme, endpoint, arbitrary_origin, self.check_endpoint(client, scheme, target, endpoint, timeout, arbitrary_origin)))
                        # Test configured malicious origins
                        for origin_template in malicious_origins:
                            origin = origin_template.format(domain=target)
                            tasks.append((scheme, endpoint, origin, self.check_endpoint(client, scheme, target, endpoint, timeout, origin)))
                results_list = await asyncio.gather(*[t[3] for t in tasks], return_exceptions=True)

                for (scheme, endpoint, origin, _), result in zip(tasks, results_list):
                    if isinstance(result, Exception):
                        self.logger.error(f"Error in check_endpoint for {scheme} {endpoint} with origin {origin}: {result}")
                        continue
                    endpoint_result, acao_values = result
                    for acao in acao_values:
                        weak_type = None
                        detail = acao
                        # If testing target origin, check for unexpected domains/IPs
                        if origin == f"{scheme}://{target}":
                            if acao != target:
                                # Check if acao is an IP
                                is_ip = bool(self.extract_ips(acao))
                                weak_type = "leaked_ip" if is_ip else "leaked_domain"
                        else:
                            # Check for arbitrary origin reflection
                            is_arbitrary = acao == origin
                            # Check for regex patterns
                            is_regex = "*" in acao or acao.endswith(target)
                            if is_arbitrary:
                                weak_type = "arbitrary"
                            elif is_regex:
                                weak_type = "regex"
                                # Test regex vulnerability with a crafted origin
                                crafted_origin = f"http://not-{acao.replace('*', '')}" if "*" in acao else f"http://not-{acao}"
                                test_result, test_acao_values = await self.check_endpoint(client, scheme, target, endpoint, timeout, crafted_origin)
                                if crafted_origin in test_acao_values:
                                    detail = f"{acao} (vulnerable to {crafted_origin})"
                        if weak_type:
                            issue = {
                                "scheme": scheme,
                                "hostname": target,
                                "endpoint": endpoint,
                                "weak_type": weak_type,
                                "detail": detail,
                                "status": "uncategorized"
                            }
                            issue_key = (scheme, target, endpoint, weak_type, detail)
                            if issue_key not in detected_keys:
                                detected_keys.add(issue_key)
                                handled_issue = self._handle_issue(issue, state_issues, endpoint_result, detail, acao)
                                if handled_issue:
                                    detected_issues.append(handled_issue)
                                    results["issues"].append({"url": endpoint_result, "weak_type": weak_type, "detail": detail, "acao": acao})

            # Remove issues no longer detected (uncategorized) or mark wont_fix as fixed
            new_issues = []
            for issue in state_issues:
                issue_key = (issue["scheme"], issue["hostname"], issue["endpoint"], issue["weak_type"], issue["detail"])
                if issue_key in detected_keys:
                    new_issues.append(issue)
                elif issue["status"] == "uncategorized":
                    self.logger.debug(f"Removing uncategorized issue {issue_key}")
                elif issue["status"] == "wont_fix":
                    self.logger.debug(f"Marking wont-fix issue {issue_key} as fixed")
                    issue["status"] = "fixed"
                    new_issues.append(issue)
                else:
                    new_issues.append(issue)

            self.state["acao-weak"]["issues"] = new_issues + detected_issues
            self.logger.debug(f"Updated state: {self.state['acao-weak']}")
            if not results["issues"]:
                self.logger.info(f"[cyan]No weak ACAO configurations found on {self.target} for either HTTP or HTTPS[/cyan]")
        except Exception as e:
            self.logger.error(f"Weak ACAO scan failed: {type(e).__name__} {e}")
        finally:
            self._is_scanning = False
        self.run_result = results
        return results

    async def check_endpoint(self, client: httpx.AsyncClient, scheme: str, target: str, endpoint: str, timeout: float, origin: str) -> tuple[str, List[str]]:
        self.logger.debug(f"Checking {scheme} endpoint {endpoint} on {target} with origin {origin}")
        max_retries = 3
        for attempt in range(max_retries):
            try:
                url = urllib.parse.urljoin(f"{scheme}://{target}", endpoint)
                headers = {"Origin": origin}
                self.logger.debug(f"Sending HEAD request to {url} with Origin: {origin}")
                r = await client.head(url, headers=headers, timeout=timeout)
                with self._lock:
                    self.endpoints_scanned += 1
                acao = r.headers.get("access-control-allow-origin", "")
                acao_values = [v.strip() for v in acao.split() if v.strip()]  # Split on spaces
                self.logger.debug(f"Response status: {r.status_code}, ACAO: {acao_values}")
                return f"{scheme}://{target}{endpoint}", acao_values
            except httpx.ConnectError as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                with self._lock:
                    self.endpoints_scanned += 1
                self.logger.debug(f"Connection error checking {scheme} {endpoint}: {e}")
                self.logger.warning(f"Connection error for {scheme}://{target}{endpoint}: {type(e).__name__} {e}")
                return f"{scheme}://{target}{endpoint}", []
            except httpx.HTTPError as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                with self._lock:
                    self.endpoints_scanned += 1
                self.logger.debug(f"HTTP error checking {scheme} {endpoint}: {e}")
                self.logger.warning(f"HTTP error for {scheme}://{target}{endpoint}: {type(e).__name__} {e}")
                return f"{scheme}://{target}{endpoint}", []
            except Exception as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                with self._lock:
                    self.endpoints_scanned += 1
                self.logger.error(f"Unexpected error checking {scheme} {endpoint}: {type(e).__name__} {e}")
                return f"{scheme}://{target}{endpoint}", []
        with self._lock:
            self.endpoints_scanned += 1
        return f"{scheme}://{target}{endpoint}", []

    def _handle_issue(self, issue: Dict, state_issues: List[Dict], endpoint: str, detail: str, acao: str) -> Dict | None:
        issue_key = (issue["scheme"], issue["hostname"], issue["endpoint"], issue["weak_type"], issue["detail"])
        for existing_issue in state_issues:
            if (existing_issue["scheme"] == issue["scheme"] and
                existing_issue["hostname"] == issue["hostname"] and
                existing_issue["endpoint"] == issue["endpoint"] and
                existing_issue["weak_type"] == issue["weak_type"] and
                existing_issue["detail"] == issue["detail"]):
                status = existing_issue["status"]
                if status == "fixed":
                    self.logger.error(f"Previously fixed weak ACAO {issue_key} re-detected on {self.target}")
                    existing_issue["status"] = "uncategorized"
                    return existing_issue
                elif status == "false_positive":
                    self.logger.error(f"Previously false-positive weak ACAO {issue_key} still detected on {self.target}")
                    existing_issue["status"] = "uncategorized"
                    return existing_issue
                elif status == "uncategorized":
                    self.logger.warning(f"Weak ACAO configuration ({detail}) on {endpoint}: ACAO={acao}")
                    return None
                return None
        self.logger.warning(f"New weak ACAO configuration ({detail}) on {endpoint}: ACAO={acao}")
        return issue

    def extract_ips(self, text: str) -> List[str]:
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.findall(ip_pattern, text)
        valid_ips = []
        for ip in matches:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                self.logger.debug(f"Invalid IP found in text: {ip}")
        return valid_ips

    def get_progress(self) -> str:
        with self._lock:
            if self.total_endpoints > 0:
                return f" {self.endpoints_scanned}/{self.total_endpoints}"
        return ""
