import asyncio
import httpx
from .base import BaseScanner
from mch.utils import setup_logging
from typing import Dict, Any, List
import urllib.parse
from rich import print as rich_print

class AcaoWeakScanner(BaseScanner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.endpoints_scanned = 0
        self.total_endpoints = 0
        self._is_scanning = False
        self.run_result = None
        self.logger = setup_logging()

    def is_scanning(self) -> bool:
        return self._is_scanning

    async def check_endpoint(self, client: httpx.AsyncClient, scheme: str, target: str, endpoint: str, timeout: float, malicious_origins: List[str]) -> tuple[str, bool, str | None]:
        """Check an endpoint for weak ACAO configurations for a specific scheme."""
        self.logger.debug(f"Checking {scheme} endpoint {endpoint} on {target}")
        try:
            url = urllib.parse.urljoin(f"{scheme}://{target}", endpoint)
            for origin in malicious_origins:
                headers = {"Origin": origin.format(domain=target)}
                self.logger.debug(f"Sending HEAD request to {url} with Origin: {headers['Origin']}")
                r = await client.head(url, headers=headers, timeout=timeout)
                self.endpoints_scanned += 1
                acao = r.headers.get("access-control-allow-origin")
                self.logger.debug(f"Response status: {r.status_code}, ACAO: {acao}")
                if acao and acao == headers["Origin"]:
                    return endpoint, True, acao
            return endpoint, False, None
        except httpx.HTTPError as e:
            self.endpoints_scanned += 1
            self.logger.warning(f"HTTP error checking {scheme} {endpoint}: {e}")
            return endpoint, False, None
        except Exception as e:
            self.endpoints_scanned += 1
            self.logger.error(f"Unexpected error checking {scheme} {endpoint}: {type(e).__name__} {e}")
            return endpoint, False, None

    async def run(self) -> Dict[str, Any]:
        results = {"issues": []}
        self.logger.debug(f"Starting AcaoWeakScanner for target: {self.target}")
        target = str(self.target)
        parsed = urllib.parse.urlparse(target if target.startswith("http") else f"http://{target}")
        target = parsed.hostname
        if not target:
            self.logger.error(f"Invalid target: {self.target}")
            rich_print(f"[red]Invalid target: {self.target}[/red]")
            return results

        endpoints = self.config.get("acao-weak", "endpoints", ["/"])
        malicious_origins = self.config.get("acao-weak", "malicious_origins", ["http://malicious-{domain}"])
        timeout = self.config.get("acao-weak", "timeout", 5.0)
        schemes = ["http", "https"]
        self.total_endpoints = len(endpoints) * len(schemes)
        self._is_scanning = True

        # Log configuration
        self.logger.debug(f"Configuration - endpoints: {endpoints}")
        self.logger.debug(f"Configuration - malicious_origins: {malicious_origins}")

        # Validate configuration
        if not isinstance(endpoints, list) or not all(isinstance(e, str) for e in endpoints):
            self.logger.error(f"Invalid endpoints configuration: {endpoints}")
            rich_print(f"[red]Invalid endpoints configuration: {endpoints}[/red]")
            return results
        if not isinstance(malicious_origins, list) or not all(isinstance(o, str) for o in malicious_origins):
            self.logger.error(f"Invalid malicious_origins configuration: {malicious_origins}")
            rich_print(f"[red]Invalid malicious_origins configuration: {malicious_origins}[/red]")
            return results

        # Initialize state
        self.logger.debug(f"Initial state: {self.state.get('acao-weak', {})}")
        if "acao-weak" not in self.state or not isinstance(self.state["acao-weak"], dict):
            self.logger.debug("Initializing acao-weak state")
            self.state["acao-weak"] = {"issues": {}}
        state_issues = self.state["acao-weak"].get("issues", {})
        self.logger.debug(f"State issues for acao-weak: {state_issues}")

        try:
            async with httpx.AsyncClient(verify=False) as client:
                for scheme in schemes:
                    tasks = [self.check_endpoint(client, scheme, target, endpoint, timeout, malicious_origins) for endpoint in endpoints]
                    results_list = await asyncio.gather(*tasks, return_exceptions=True)
                    for endpoint, result in zip(endpoints, results_list):
                        if isinstance(result, Exception):
                            self.logger.error(f"Error scanning {scheme} {endpoint}: {result}")
                            continue
                        endpoint, found, acao = result
                        if found and acao:
                            issue_key = f"weak-acao:{scheme}://{target}{endpoint}"
                            self.logger.debug(f"Detected weak ACAO: {issue_key}")
                            if issue_key in state_issues:
                                status = state_issues[issue_key]
                                if status == "fixed":
                                    rich_print(f"[red]Previously fixed weak ACAO {issue_key} re-detected on {self.target}[/red]")
                                    state_issues[issue_key] = "uncategorized"
                                elif status in ["false-positive", "wont-fix"]:
                                    rich_print(f"[red]Previously {status} weak ACAO {issue_key} still detected on {self.target}[/red]")
                                    state_issues[issue_key] = "uncategorized"
                            else:
                                state_issues[issue_key] = "uncategorized"
                                rich_print(f"[yellow]Warning: Weak ACAO configuration on {scheme}://{target}{endpoint}: {acao}[/yellow]")
                                results["issues"].append({"url": f"{scheme}://{target}{endpoint}", "acao": acao})

            for issue_key in list(state_issues.keys()):
                if not any(issue_key == f"weak-acao:{scheme}://{target}{endpoint}" for scheme in schemes for endpoint in endpoints if f"{scheme}://{target}{endpoint}" in [issue["url"] for issue in results["issues"]]):
                    status = state_issues[issue_key]
                    self.logger.debug(f"Checking state for {issue_key}: status={status}")
                    if status == "uncategorized":
                        self.logger.debug(f"Removing uncategorized issue {issue_key}")
                        del state_issues[issue_key]
                    elif status == "wont-fix":
                        self.logger.debug(f"Marking wont-fix issue {issue_key} as fixed")
                        state_issues[issue_key] = "fixed"

            if not results["issues"]:
                rich_print(f"[cyan]No weak ACAO configurations found on {self.target} for either HTTP or HTTPS[/cyan]")

            self.state["acao-weak"]["issues"] = state_issues
            self.logger.debug(f"Updated state: {self.state['acao-weak']}")
            self.save()
            self.logger.debug("State saved")
        except Exception as e:
            self.logger.error(f"Weak ACAO scan failed: {type(e).__name__} {e}")
            rich_print(f"[red]Weak ACAO scan failed: {type(e).__name__} {e}[/red]")
        finally:
            self._is_scanning = False
        self.run_result = results
        return results

    def get_progress(self) -> str:
        if self.total_endpoints > 0:
            return f" {self.endpoints_scanned}/{self.total_endpoints}"
        return ""
