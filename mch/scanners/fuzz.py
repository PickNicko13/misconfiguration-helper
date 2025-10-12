import asyncio
import httpx
from .base import BaseScanner
from mch.utils import setup_logging
from typing import Dict, Any
from pathlib import Path
from threading import Lock
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

    async def probe_scheme(self, client: httpx.AsyncClient, scheme: str, target: str, timeout: float, max_retries: int = 3) -> bool:
        url = f"{scheme}://{target}/"
        backoff = 1.0
        for attempt in range(max_retries):
            try:
                self.logger.debug(f"Probing {scheme}://{target}/ (attempt {attempt + 1})")
                r = await client.head(url, timeout=timeout)
                if r.status_code < 500:
                    self.logger.debug(f"Scheme {scheme} responsive (code: {r.status_code})")
                    return True
            except httpx.ConnectError as e:
                self.logger.debug(f"Probe {scheme} connection failed (attempt {attempt + 1}): {e}")
                self.logger.warning(f"Connection error probing {scheme}://{target}: {type(e).__name__} {e}")
            except httpx.HTTPError as e:
                self.logger.debug(f"Probe {scheme} HTTP failed (attempt {attempt + 1}): {e}")
                self.logger.warning(f"HTTP error probing {scheme}://{target}: {type(e).__name__} {e}")
            except Exception as e:
                self.logger.debug(f"Probe {scheme} unexpected failed (attempt {attempt + 1}): {e}")
                self.logger.error(f"Unexpected error probing {scheme}://{target}: {type(e).__name__} {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(backoff)
                backoff *= 2
        self.logger.debug(f"Scheme {scheme} unresponsive after {max_retries} probes; skipping")
        self.logger.warning(f"Skipping fuzz on {scheme}://{target} (unresponsive after {max_retries} probes)")
        return False

    async def run_async(self) -> Dict[str, Any]:
        results = {"found": []}
        self.logger.debug(f"Starting fuzz scan on {self.target}")
        target = str(self.target)
        parsed = urllib.parse.urlparse(target if target.startswith("http") else f"http://{target}")
        target = parsed.hostname
        if not target:
            self.logger.error(f"Invalid target: {self.target}")
            return results

        wordlist_files = self.config.get("fuzz", "wordlist", str(Path(__file__).parent / "wordlists" / "directory-list-2.3-small.txt"))
        if isinstance(wordlist_files, str):
            wordlist_files = [wordlist_files.strip() for wordlist_files in wordlist_files.split(",") if wordlist_files.strip()]
        elif not isinstance(wordlist_files, list):
            self.logger.error(f"Invalid wordlist config: {wordlist_files} (must be string or list)")
            return results

        wordlist = []
        for file_path in wordlist_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    wordlist.extend(line.strip() for line in f if line.strip())
            except Exception as e:
                self.logger.error(f"Failed to load wordlist {file_path}: {e}")
        if not wordlist:
            self.logger.error("No valid wordlist loaded; cannot proceed with fuzz scan")
            return results

        extensions = self.config.get("fuzz", "extensions", [])
        timeout = self.config.get("fuzz", "timeout", 5.0)
        delay = self.config.get("fuzz", "delay", 0.0)
        concurrency = self.config.get("fuzz", "concurrency", 50)
        schemes = ["http", "https"]
        viable_schemes = []
        self.total_paths = 0
        issues = []

        with self._lock:
            self._is_scanning = True
        try:
            async with httpx.AsyncClient(verify=False) as client:
                probe_tasks = [self.probe_scheme(client, scheme, target, timeout) for scheme in schemes]
                probe_results = await asyncio.gather(*probe_tasks)
                for scheme, viable in zip(schemes, probe_results):
                    if viable:
                        viable_schemes.append(scheme)
                        self.total_paths += len(wordlist) * (1 + len(extensions))

                if not viable_schemes:
                    self.logger.warning(f"No viable schemes for fuzz on {self.target}; aborting")
                    return results

                semaphore = asyncio.Semaphore(concurrency)
                for scheme in viable_schemes:
                    tasks = []
                    for word in wordlist:
                        for ext in [""] + extensions:
                            path = f"/{word}{ext}"
                            task = self.scan_path(client, scheme, target, path, timeout, delay, semaphore)
                            tasks.append((path, task))
                    results_chunk = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)
                    for (path, _), result in zip(tasks, results_chunk):
                        if isinstance(result, Exception):
                            self.logger.debug(f"Error scanning {scheme} {path} on {target}: {result}")
                            continue
                        success, status_code = result
                        if success:
                            issue_key = f"{scheme}://{target}{path}"
                            issues.append(issue_key)
                            self.logger.warning(f"Exposed file/dir on {scheme}://{target}{path} (code: {status_code})")
            self.state["fuzz"]["issues"] = sorted(set(self.state["fuzz"].get("issues", []) + issues))
            results["found"] = issues
            if not issues:
                self.logger.info(f"[cyan]No exposed files/dirs on {self.target} for viable schemes ({', '.join(viable_schemes)})[/cyan]")
        except Exception as e:
            self.logger.error(f"Fuzz scan failed: {type(e).__name__} {e}")
        finally:
            with self._lock:
                self._is_scanning = False
        self.run_result = results
        return results

    async def scan_path(self, client: httpx.AsyncClient, scheme: str, target: str, path: str, timeout: float, delay: float, semaphore: asyncio.Semaphore) -> tuple[bool, int | None]:
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
                    if r.status_code == 200:
                        body_lower = r.text.lower()
                        if "404" in body_lower or "not found" in body_lower:
                            self.logger.debug(f"Detected custom 404 for {url} (body indicators)")
                            return False, 200
                    if r.status_code in [200, 301, 302]:
                        return True, r.status_code
                    return False, None
                except httpx.ConnectError as e:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(backoff)
                        backoff *= 2
                        continue
                    with self._lock:
                        self.paths_scanned += 1
                    self.logger.debug(f"Connection error fuzzing {scheme} {path} on {target}: {e}")
                    self.logger.warning(f"Connection error for {scheme}://{target}{path}: {type(e).__name__} {e}")
                    return False, None
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 429:
                        await asyncio.sleep(backoff)
                        backoff *= 2
                        continue
                    else:
                        with self._lock:
                            self.paths_scanned += 1
                        self.logger.debug(f"HTTP error fuzzing {scheme} {path} on {target}: {e}")
                        self.logger.warning(f"HTTP error for {scheme}://{target}{path}: {type(e).__name__} {e}")
                        return False, None
                except Exception as e:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(backoff)
                        backoff *= 2
                        continue
                    with self._lock:
                        self.paths_scanned += 1
                    self.logger.debug(f"Error fuzzing {scheme} {path} on {target}: {type(e).__name__} {e}")
                    self.logger.error(f"Unexpected error for {scheme}://{target}{path}: {type(e).__name__} {e}")
                    return False, None
            with self._lock:
                self.paths_scanned += 1
            return False, None

    def get_progress(self) -> str:
        with self._lock:
            if self.total_paths > 0:
                return f" {self.paths_scanned}/{self.total_paths}"
        return ""
