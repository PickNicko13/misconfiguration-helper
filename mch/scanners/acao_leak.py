import httpx
from .base import BaseScanner
from mch.utils import setup_logging
from typing import Dict, Any, List
import urllib.parse
import ipaddress
import re
from rich import print as rich_print

class AcaoLeakScanner(BaseScanner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.endpoints_scanned = 0
        self.total_endpoints = 0
        self._is_scanning = False
        self.run_result = None
        self.logger = setup_logging()

    def is_scanning(self) -> bool:
        return self._is_scanning

    def check_endpoint(self, client: httpx.Client, scheme: str, target: str, endpoint: str, timeout: float) -> tuple[str, bool, str | None]:
        """Check an endpoint for ACAO leaks for a specific scheme."""
        self.logger.debug(f"Checking {scheme} endpoint {endpoint} on {target}")
        try:
            url = urllib.parse.urljoin(f"{scheme}://{target}", endpoint)
            headers = {"Origin": "http://evil.com"}
            self.logger.debug(f"Sending HEAD request to {url} with Origin: http://evil.com")
            r = client.head(url, headers=headers, timeout=timeout)
            self.endpoints_scanned += 1
            acao = r.headers.get("access-control-allow-origin")
            self.logger.debug(f"Response status: {r.status_code}, ACAO: {acao}")
            self.logger.debug(f"Full headers: {dict(r.headers)}")
            if acao:
                return endpoint, True, acao
            return endpoint, False, None
        except httpx.ConnectError as e:
            self.endpoints_scanned += 1
            self.logger.debug(f"Connection error checking {scheme} {endpoint}: {e}")
            rich_print(f"[yellow]Connection error for {scheme}://{target}{endpoint}: {type(e).__name__} {e}[/yellow]")
            return endpoint, False, None
        except httpx.HTTPError as e:
            self.endpoints_scanned += 1
            self.logger.debug(f"HTTP error checking {scheme} {endpoint}: {e}")
            rich_print(f"[yellow]HTTP error for {scheme}://{target}{endpoint}: {type(e).__name__} {e}[/yellow]")
            return endpoint, False, None
        except Exception as e:
            self.endpoints_scanned += 1
            self.logger.error(f"Unexpected error checking {scheme} {endpoint}: {type(e).__name__} {e}")
            rich_print(f"[red]Unexpected error for {scheme}://{target}{endpoint}: {type(e).__name__} {e}[/red]")
            return endpoint, False, None

    def extract_ips(self, text: str) -> List[str]:
        """Extract all valid IP addresses from text."""
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

    def run(self) -> Dict[str, Any]:
        results = {"leaks": []}
        self.logger.debug(f"Starting AcaoLeakScanner for target: {self.target}")
        target = str(self.target)
        parsed = urllib.parse.urlparse(target if target.startswith("http") else f"http://{target}")
        target = parsed.hostname
        if not target:
            self.logger.error(f"Invalid target: {self.target}")
            rich_print(f"[red]Invalid target: {self.target}[/red]")
            return results

        endpoints = self.config.get("acao-leak", "endpoints", ["/"])
        trusted = self.config.get("acao-leak", "trusted_origins", [])
        timeout = self.config.get("acao-leak", "timeout", 5.0)
        schemes = ["http", "https"]
        self.total_endpoints = len(endpoints) * len(schemes)
        self._is_scanning = True

        # Log configuration
        self.logger.debug(f"Configuration - endpoints: {endpoints}")
        self.logger.debug(f"Configuration - trusted_origins: {trusted}")

        # Validate configuration
        if not isinstance(endpoints, list) or not all(isinstance(e, str) for e in endpoints):
            self.logger.error(f"Invalid endpoints configuration: {endpoints}")
            rich_print(f"[red]Invalid endpoints configuration: {endpoints}[/red]")
            return results
        if not isinstance(trusted, list) or not all(isinstance(t, str) for t in trusted):
            self.logger.error(f"Invalid trusted_origins configuration: {trusted}")
            rich_print(f"[red]Invalid trusted_origins configuration: {trusted}[/red]")
            return results

        # Initialize state
        self.logger.debug(f"Initial state: {self.state.get('acao-leak', {})}")
        if "acao-leak" not in self.state or not isinstance(self.state["acao-leak"], dict):
            self.logger.debug("Initializing acao-leak state")
            self.state["acao-leak"] = {"issues": {}}
        state_issues = self.state["acao-leak"].get("issues", {})
        self.logger.debug(f"State issues for acao-leak: {state_issues}")

        try:
            with httpx.Client(verify=False) as client:
                for scheme in schemes:
                    for endpoint in endpoints:
                        endpoint, found, acao = self.check_endpoint(client, scheme, target, endpoint, timeout)
                        if found and acao:
                            extracted_ips = self.extract_ips(acao)
                            self.logger.debug(f"Extracted IPs from ACAO: {extracted_ips}")
                            is_leak = acao == "*" or len(extracted_ips) > 0
                            self.logger.debug(f"ACAO leak check - wildcard: {acao == '*'}, has_ips: {len(extracted_ips) > 0}, is_leak: {is_leak}")
                            if acao != "*" and acao not in trusted and is_leak:
                                for ip in extracted_ips:
                                    issue_key = f"leak-ip:{scheme}://{target}{endpoint}:{ip}"
                                    self.logger.debug(f"Detected leak: {issue_key}")
                                    if issue_key in state_issues:
                                        status = state_issues[issue_key]
                                        if status == "fixed":
                                            rich_print(f"[red]Previously fixed ACAO leak {issue_key} re-detected on {self.target}[/red]")
                                            state_issues[issue_key] = "uncategorized"
                                        elif status == "false-positive":
                                            rich_print(f"[red]Previously false-positive ACAO leak {issue_key} still detected on {self.target}[/red]")
                                            state_issues[issue_key] = "uncategorized"
                                        elif status == "uncategorized":
                                            rich_print(f"[yellow]Warning: ACAO leak IP address on {scheme}://{target}{endpoint}: {ip} (ACAO: {acao})[/yellow]")
                                    else:
                                        state_issues[issue_key] = "uncategorized"
                                        rich_print(f"[yellow]Warning: ACAO leak IP address on {scheme}://{target}{endpoint}: {ip} (ACAO: {acao})[/yellow]")
                                    results["leaks"].append({"url": f"{scheme}://{target}{endpoint}", "ip": ip, "acao": acao})

            # Remove issues no longer detected
            for issue_key in list(state_issues.keys()):
                if not any(issue_key == f"leak-ip:{scheme}://{target}{endpoint}:{leak['ip']}" for scheme in schemes for endpoint in endpoints for leak in results["leaks"] if leak["url"] == f"{scheme}://{target}{endpoint}"):
                    status = state_issues[issue_key]
                    self.logger.debug(f"Checking state for {issue_key}: status={status}")
                    if status == "uncategorized":
                        self.logger.debug(f"Removing uncategorized issue {issue_key}")
                        del state_issues[issue_key]
                    elif status == "wont-fix":
                        self.logger.debug(f"Marking wont-fix issue {issue_key} as fixed")
                        state_issues[issue_key] = "fixed"

            if not results["leaks"]:
                rich_print(f"[cyan]No ACAO leaks found on {self.target} for HTTP and HTTPS[/cyan]")

            self.state["acao-leak"]["issues"] = state_issues
            self.logger.debug(f"Updated state: {self.state['acao-leak']}")
            self.save()
            self.logger.debug("State saved")
        except Exception as e:
            self.logger.error(f"ACAO leak scan failed: {type(e).__name__} {e}")
            rich_print(f"[red]ACAO leak scan failed: {type(e).__name__} {e}[/red]")
        finally:
            self._is_scanning = False
        self.run_result = results
        return results

    def extract_ips(self, text: str) -> List[str]:
        """Extract all valid IP addresses from text."""
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
        if self.total_endpoints > 0:
            return f" {self.endpoints_scanned}/{self.total_endpoints}"
        return ""
