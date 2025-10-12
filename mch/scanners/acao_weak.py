import asyncio
import httpx
from .base import BaseScanner
from mch.utils import setup_logging
from typing import Dict, Any, List
import urllib.parse
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
        self.total_endpoints = len(endpoints) * len(schemes) * len(malicious_origins)
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
            self.state["acao-weak"] = {"issues": {}}
        state_issues = self.state["acao-weak"].get("issues", {})
        self.logger.debug(f"State issues for acao-weak: {state_issues}")

        detected_keys = set()

        try:
            async with httpx.AsyncClient(verify=False) as client:
                for scheme in schemes:
                    for endpoint in endpoints:
                        for origin_template in malicious_origins:
                            origin = origin_template.format(domain=target)
                            endpoint_result, found, acao = await self.check_endpoint(client, scheme, target, endpoint, timeout, origin)
                            if found and acao:
                                issue_key = f"{scheme}/{target}{endpoint}/weak/{origin}"
                                detected_keys.add(issue_key)
                                self.logger.debug(f"Detected weak ACAO: {issue_key}")
                                if issue_key in state_issues:
                                    status = state_issues[issue_key]
                                    if status == "fixed":
                                        self.logger.error(f"Previously fixed weak ACAO {issue_key} re-detected on {self.target}")
                                        state_issues[issue_key] = "uncategorized"
                                    elif status in ["false_positive", "wont_fix"]:
                                        self.logger.error(f"Previously {status} weak ACAO {issue_key} still detected on {self.target}")
                                        state_issues[issue_key] = "uncategorized"
                                else:
                                    state_issues[issue_key] = "uncategorized"
                                    self.logger.warning(f"Weak ACAO configuration on {endpoint_result}: {acao}")
                                    results["issues"].append({"url": endpoint_result, "origin": origin, "acao": acao})

            for issue_key in list(state_issues.keys()):
                if issue_key not in detected_keys:
                    status = state_issues[issue_key]
                    self.logger.debug(f"Checking state for {issue_key}: status={status}")
                    if status == "uncategorized":
                        self.logger.debug(f"Removing uncategorized issue {issue_key}")
                        del state_issues[issue_key]
                    elif status == "wont_fix":
                        self.logger.debug(f"Marking wont-fix issue {issue_key} as fixed")
                        state_issues[issue_key] = "fixed"

            if not results["issues"]:
                self.logger.info(f"[cyan]No weak ACAO configurations found on {self.target} for either HTTP or HTTPS[/cyan]")

            self.state["acao-weak"]["issues"] = state_issues
            self.logger.debug(f"Updated state: {self.state['acao-weak']}")
            self.save()
            self.logger.debug("State saved")
        except Exception as e:
            self.logger.error(f"Weak ACAO scan failed: {type(e).__name__} {e}")
        finally:
            self._is_scanning = False
        self.run_result = results
        return results

    async def check_endpoint(self, client: httpx.AsyncClient, scheme: str, target: str, endpoint: str, timeout: float, origin: str) -> tuple[str, bool, str | None]:
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
                acao = r.headers.get("access-control-allow-origin")
                self.logger.debug(f"Response status: {r.status_code}, ACAO: {acao}")
                if acao and acao == origin:
                    return f"{scheme}://{target}{endpoint}", True, acao
                return f"{scheme}://{target}{endpoint}", False, None
            except httpx.ConnectError as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                with self._lock:
                    self.endpoints_scanned += 1
                self.logger.debug(f"Connection error checking {scheme} {endpoint}: {e}")
                self.logger.warning(f"Connection error for {scheme}://{target}{endpoint}: {type(e).__name__} {e}")
                return f"{scheme}://{target}{endpoint}", False, None
            except httpx.HTTPError as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                with self._lock:
                    self.endpoints_scanned += 1
                self.logger.debug(f"HTTP error checking {scheme} {endpoint}: {e}")
                self.logger.warning(f"HTTP error for {scheme}://{target}{endpoint}: {type(e).__name__} {e}")
                return f"{scheme}://{target}{endpoint}", False, None
            except Exception as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                with self._lock:
                    self.endpoints_scanned += 1
                self.logger.error(f"Unexpected error checking {scheme} {endpoint}: {type(e).__name__} {e}")
                return f"{scheme}://{target}{endpoint}", False, None
        with self._lock:
            self.endpoints_scanned += 1
        return f"{scheme}://{target}{endpoint}", False, None

    def get_progress(self) -> str:
        with self._lock:
            if self.total_endpoints > 0:
                return f" {self.endpoints_scanned}/{self.total_endpoints}"
        return ""
