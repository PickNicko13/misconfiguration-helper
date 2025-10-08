import asyncio
import httpx
from .base import BaseScanner
from mch.utils import setup_logging
from typing import Dict, Any
from pathlib import Path
from threading import Lock
from rich import print as rich_print
import urllib.parse

class FuzzScanner(BaseScanner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.paths_scanned = 0
        self.total_paths = 0
        self._is_scanning = False
        self.run_result = None
        self._lock = Lock()
        self.logger = setup_logging()

    def is_scanning(self) -> bool:
        with self._lock:
            return self._is_scanning

    async def scan_path(self, client: httpx.AsyncClient, scheme: str, target: str, path: str, timeout: float, delay: float, semaphore: asyncio.Semaphore) -> tuple[bool, int | None]:
        """Attempt to access a single path asynchronously with delay and backoff for a specific scheme."""
        async with semaphore:
            backoff = 1.0
            max_retries = 3
            for attempt in range(max_retries):
                await asyncio.sleep(delay)
                try:
                    url = f"{scheme}://{target}{path}"
                    self.logger.debug(f"Sending GET request to {url}")
                    r = await client.get(url, timeout=timeout)
                    with self._lock:
                        self.paths_scanned += 1
                    if r.status_code in [200, 301, 302]:
                        return True, r.status_code
                    return False, None
                except httpx.HTTPStatusError as e:
                    with self._lock:
                        self.paths_scanned += 1
                    if e.response.status_code == 429:
                        await asyncio.sleep(backoff)
                        backoff *= 2
                        continue
                    else:
                        self.logger.debug(f"HTTP error fuzzing {scheme} {path} on {target}: {e}")
                        return False, None
                except Exception as e:
                    with self._lock:
                        self.paths_scanned += 1
                    self.logger.debug(f"Error fuzzing {scheme} {path} on {target}: {type(e).__name__} {e}")
                    return False, None
            return False, None

    async def run(self) -> Dict[str, Any]:
        results = {"found": []}
        self.logger.debug(f"Starting fuzz scan on {self.target}")
        target = str(self.target)
        parsed = urllib.parse.urlparse(target if target.startswith("http") else f"http://{target}")
        target = parsed.hostname
        if not target:
            self.logger.error(f"Invalid target: {self.target}")
            rich_print(f"[red]Invalid target: {self.target}[/red]")
            return results

        wordlist_files = self.config.get("fuzz", "wordlist", str(Path(__file__).parent / "wordlists" / "directory-list-2.3-small.txt"))
        if isinstance(wordlist_files, str):
            wordlist_files = [wordlist_files.strip() for wordlist_files in wordlist_files.split(",") if wordlist_files.strip()]
        elif not isinstance(wordlist_files, list):
            self.logger.error(f"Invalid wordlist config: {wordlist_files} (must be string or list)")
            rich_print(f"[red]Invalid wordlist config: {wordlist_files}[/red]")
            return results

        wordlist = []
        for file_path in wordlist_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    wordlist.extend(line.strip() for line in f if line.strip())
            except Exception as e:
                self.logger.error(f"Failed to load wordlist {file_path}: {e}")
                rich_print(f"[red]Failed to load wordlist {file_path}: {e}[/red]")
        if not wordlist:
            self.logger.error("No valid wordlist loaded; cannot proceed with fuzz scan")
            rich_print(f"[red]No valid wordlist loaded; cannot proceed with fuzz scan[/red]")
            return results

        extensions = self.config.get("fuzz", "extensions", [])
        timeout = self.config.get("fuzz", "timeout", 5.0)
        delay = self.config.get("fuzz", "delay", 0.0)
        concurrency = self.config.get("fuzz", "concurrency", 50)
        schemes = ["http", "https"]
        self.total_paths = len(wordlist) * (1 + len(extensions)) * len(schemes)
        issues = []

        with self._lock:
            self._is_scanning = True
        try:
            async with httpx.AsyncClient(verify=False) as client:
                semaphore = asyncio.Semaphore(concurrency)
                for scheme in schemes:
                    tasks = [
                        self.scan_path(client, scheme, target, f"/{word}{ext}", timeout, delay, semaphore)
                        for word in wordlist
                        for ext in [""] + extensions
                    ]
                    results_chunk = await asyncio.gather(*tasks, return_exceptions=True)
                    for path, result in zip([f"/{word}{ext}" for word in wordlist for ext in [""] + extensions], results_chunk):
                        if isinstance(result, Exception):
                            self.logger.debug(f"Error scanning {scheme} {path} on {target}: {result}")
                            continue
                        success, status_code = result
                        if success:
                            issue_key = f"{scheme}://{target}{path}"
                            issues.append(issue_key)
                            rich_print(f"[yellow]Warning: Exposed file/dir on {scheme}://{target}{path} (code: {status_code})[/yellow]")
            self.state["fuzz"]["issues"] = sorted(set(self.state["fuzz"].get("issues", []) + issues))
            results["found"] = issues
            if not issues:
                rich_print(f"[cyan]No exposed files/dirs on {self.target} for either HTTP or HTTPS[/cyan]")
        except Exception as e:
            self.logger.error(f"Fuzz scan failed: {type(e).__name__} {e}")
            rich_print(f"[red]Fuzz scan failed: {type(e).__name__} {e}[/red]")
        finally:
            with self._lock:
                self._is_scanning = False
        self.run_result = results
        self.save()
        return results

    def get_progress(self) -> str:
        with self._lock:
            if self.total_paths > 0:
                return f" {self.paths_scanned}/{self.total_paths}"
            return ""
