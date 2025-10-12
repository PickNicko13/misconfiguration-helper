import httpx
import asyncio
from .base import BaseScanner
from mch.utils import setup_logging
from typing import Dict, Any, List
import urllib.parse
import ipaddress
import re
from threading import Lock

class AcaoLeakScanner(BaseScanner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.endpoints_scanned = 0
        self.total_endpoints = 0
        self._is_scanning = False
        self.run_result = None
        self._lock = Lock()
        self.logger = setup_logging()

    async def run_async(self) -> Dict[str, Any]:
        results = {"leaks": []}
        self.logger.debug(f"Starting AcaoLeakScanner for target: {self.target}")
        target = str(self.target)
        parsed = urllib.parse.urlparse(target if target.startswith("http") else f"http://{target}")
        target = parsed.hostname
        if not target:
            self.logger.error(f"Invalid target: {self.target}")
            return results

        endpoints = self.config.get("acao-leak", "endpoints", ["/"])
        trusted = self.config.get("acao-leak", "trusted_origins", [])
        timeout = self.config.get("acao-leak", "timeout", 5.0)
        request_origin = "http://evil.com"
        schemes = ["http", "https"]
        self.total_endpoints = len(endpoints) * len(schemes)
        self._is_scanning = True

        self.logger.debug(f"Configuration - endpoints: {endpoints}")
        self.logger.debug(f"Configuration - trusted_origins: {trusted}")

        if not isinstance(endpoints, list) or not all(isinstance(e, str) for e in endpoints):
            self.logger.error(f"Invalid endpoints configuration: {endpoints}")
            return results
        if not isinstance(trusted, list) or not all(isinstance(t, str) for t in trusted):
            self.logger.error(f"Invalid trusted_origins configuration: {trusted}")
            return results

        self.logger.debug(f"Initial state: {self.state.get('acao-leak', {})}")
        if "acao-leak" not in self.state or not isinstance(self.state["acao-leak"], dict):
            self.logger.debug("Initializing acao-leak state")
            self.state["acao-leak"] = {"issues": []}
        state_issues = self.state["acao-leak"].get("issues", [])
        self.logger.debug(f"State issues for acao-leak: {state_issues}")

        detected_issues = []
        detected_keys = set()  # Track unique issues to prevent duplicates

        try:
            async with httpx.AsyncClient(verify=False) as client:
                tasks = []
                for scheme in schemes:
                    for endpoint in endpoints:
                        task = self.check_endpoint_async(client, scheme, target, endpoint, timeout, request_origin, trusted)
                        tasks.append((scheme, endpoint, task))
                results_list = await asyncio.gather(*[t[2] for t in tasks], return_exceptions=True)

                for (scheme, endpoint, _), result in zip(tasks, results_list):
                    if isinstance(result, Exception):
                        self.logger.error(f"Error in check_endpoint for {scheme} {endpoint}: {result}")
                        continue
                    endpoint_result, found, acao, leak_info = result
                    if found and acao:
                        extracted_ips = self.extract_ips(acao)
                        is_wildcard = acao == "*"
                        is_reflect = acao == request_origin
                        is_ip_leak = len(extracted_ips) > 0
                        leak_type = None
                        detail = None
                        issues_to_add = []
                        if is_wildcard:
                            leak_type = "wildcard"
                            detail = "*"
                            issues_to_add.append({
                                "scheme": scheme,
                                "hostname": target,
                                "endpoint": endpoint,
                                "leak_type": leak_type,
                                "detail": detail,
                                "status": "uncategorized"
                            })
                        elif is_reflect:
                            leak_type = "reflect"
                            detail = request_origin
                            issues_to_add.append({
                                "scheme": scheme,
                                "hostname": target,
                                "endpoint": endpoint,
                                "leak_type": leak_type,
                                "detail": detail,
                                "status": "uncategorized"
                            })
                        elif is_ip_leak:
                            leak_type = "ip"
                            for ip in extracted_ips:
                                detail = ip
                                issues_to_add.append({
                                    "scheme": scheme,
                                    "hostname": target,
                                    "endpoint": endpoint,
                                    "leak_type": leak_type,
                                    "detail": detail,
                                    "status": "uncategorized"
                                })

                        for issue in issues_to_add:
                            issue_key = (issue["scheme"], issue["hostname"], issue["endpoint"], issue["leak_type"], issue["detail"])
                            if issue_key not in detected_keys and acao not in trusted:
                                detected_keys.add(issue_key)
                                handled_issue = self._handle_leak_detection(issue, state_issues, endpoint_result, detail, acao)
                                if handled_issue:
                                    detected_issues.append(handled_issue)
                                    results["leaks"].append({
                                        "url": endpoint_result,
                                        "leak_type": leak_type,
                                        "detail": detail,
                                        "acao": acao
                                    })

            # Remove issues no longer detected (uncategorized) or mark wont_fix as fixed
            new_issues = []
            for issue in state_issues:
                issue_key = (issue["scheme"], issue["hostname"], issue["endpoint"], issue["leak_type"], issue["detail"])
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

            self.state["acao-leak"]["issues"] = new_issues + detected_issues
            self.logger.debug(f"Updated state: {self.state['acao-leak']}")
            if not results["leaks"]:
                self.logger.info(f"[cyan]No ACAO leaks found on {self.target} for HTTP and HTTPS[/cyan]")
        except Exception as e:
            self.logger.error(f"ACAO leak scan failed: {type(e).__name__} {e}")
        finally:
            self._is_scanning = False
        self.run_result = results
        return results

    async def check_endpoint_async(self, client: httpx.AsyncClient, scheme: str, target: str, endpoint: str, timeout: float, request_origin: str, trusted: List[str]) -> tuple[str, bool, str | None, tuple[str | None, str | None]]:
        self.logger.debug(f"Checking {scheme} endpoint {endpoint} on {target}")
        try:
            url = urllib.parse.urljoin(f"{scheme}://{target}", endpoint)
            headers = {"Origin": request_origin}
            self.logger.debug(f"Sending HEAD request to {url} with Origin: {request_origin}")
            r = await client.head(url, headers=headers, timeout=timeout)
            with self._lock:
                self.endpoints_scanned += 1
            acao = r.headers.get("access-control-allow-origin")
            self.logger.debug(f"Response status: {r.status_code}, ACAO: {acao}")
            self.logger.debug(f"Full headers: {dict(r.headers)}")
            leak_type = None
            detail = None
            if acao:
                extracted_ips = self.extract_ips(acao)
                is_wildcard = acao == "*"
                is_reflect = acao == request_origin
                is_ip_leak = len(extracted_ips) > 0
                if is_wildcard:
                    leak_type = "wildcard"
                    detail = "*"
                elif is_reflect:
                    leak_type = "reflect"
                    detail = request_origin
                elif is_ip_leak:
                    leak_type = "ip"
                    detail = ",".join(extracted_ips)
                if acao not in trusted and (is_wildcard or is_reflect or is_ip_leak):
                    return f"{scheme}://{target}{endpoint}", True, acao, (leak_type, detail)
            return f"{scheme}://{target}{endpoint}", False, None, (None, None)
        except httpx.ConnectError as e:
            with self._lock:
                self.endpoints_scanned += 1
            self.logger.debug(f"Connection error checking {scheme} {endpoint}: {e}")
            self.logger.warning(f"Connection error for {scheme}://{target}{endpoint}: {type(e).__name__} {e}")
            return f"{scheme}://{target}{endpoint}", False, None, (None, None)
        except httpx.HTTPError as e:
            with self._lock:
                self.endpoints_scanned += 1
            self.logger.debug(f"HTTP error checking {scheme} {endpoint}: {e}")
            self.logger.warning(f"HTTP error for {scheme}://{target}{endpoint}: {type(e).__name__} {e}")
            return f"{scheme}://{target}{endpoint}", False, None, (None, None)
        except Exception as e:
            with self._lock:
                self.endpoints_scanned += 1
            self.logger.error(f"Unexpected error checking {scheme} {endpoint}: {type(e).__name__} {e}")
            return f"{scheme}://{target}{endpoint}", False, None, (None, None)

    def _handle_leak_detection(self, issue: Dict, state_issues: List[Dict], endpoint: str, detail: str, acao: str) -> Dict | None:
        issue_key = (issue["scheme"], issue["hostname"], issue["endpoint"], issue["leak_type"], issue["detail"])
        for existing_issue in state_issues:
            if (existing_issue["scheme"] == issue["scheme"] and
                existing_issue["hostname"] == issue["hostname"] and
                existing_issue["endpoint"] == issue["endpoint"] and
                existing_issue["leak_type"] == issue["leak_type"] and
                existing_issue["detail"] == issue["detail"]):
                status = existing_issue["status"]
                if status == "fixed":
                    self.logger.error(f"Previously fixed ACAO leak {issue_key} re-detected on {self.target}")
                    existing_issue["status"] = "uncategorized"
                    return existing_issue
                elif status == "false_positive":
                    self.logger.error(f"Previously false-positive ACAO leak {issue_key} still detected on {self.target}")
                    existing_issue["status"] = "uncategorized"
                    return existing_issue
                elif status == "uncategorized":
                    self.logger.warning(f"ACAO leak ({detail}) on {endpoint}: ACAO={acao}")
                    return None  # Do not re-add existing uncategorized issue
                return None
        self.logger.warning(f"New ACAO leak ({detail}) on {endpoint}: ACAO={acao}")
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
