import httpx
from bs4 import BeautifulSoup
from .base import BaseScanner
from mch.utils import setup_logging
from typing import Dict, Any
import re

class AcaoUsabilityScanner(BaseScanner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pages_scanned = 0
        self.total_pages = 0

    def run(self) -> Dict[str, Any]:
        results = {"blocks": []}
        pages = self.config.get("acao-usability", "pages", ["/"])
        self.total_pages = len(pages)
        blocks = []
        with httpx.Client(verify=False) as client:
            for page in pages:
                self.pages_scanned += 1
                url = f"https://{self.target}{page}" if self.target.startswith("http") else f"http://{self.target}{page}"
                try:
                    r = client.get(url)
                    soup = BeautifulSoup(r.text, "lxml")
                    # Extract remote URLs from JS and tags
                    remote_urls = set()
                    for script in soup.find_all("script", src=True):
                        remote_urls.add(script["src"])
                    for link in soup.find_all("link", href=True):
                        remote_urls.add(link["href"])
                    for img in soup.find_all("img", src=True):
                        remote_urls.add(img["src"])
                    # Filter remote URLs (not same origin)
                    remote_urls = [u for u in remote_urls if re.match(r"^http", u) and not u.startswith("http://" + self.target) and not u.startswith("https://" + self.target)]
                    for remote_url in remote_urls:
                        try:
                            test_r = client.options(remote_url, headers={"Origin": url})
                            if "Access-Control-Allow-Origin" not in test_r.headers or test_r.headers["Access-Control-Allow-Origin"] not in [url, "*"]:
                                entry = {"page": url, "remote_url": remote_url}
                                blocks.append(entry)
                                self.warn(f"CORS usability issue on {url}: {remote_url} blocked by browser")
                        except Exception as e:
                            self.logger.warning(f"Error checking CORS usability on {remote_url}: {e}")
                except Exception as e:
                    self.logger.warning(f"Error scanning page {url}: {e}")
        self.state["acao-usability"]["blocks"] += blocks
        results["blocks"] = blocks
        self.save()
        return results

    def get_progress(self) -> str:
        if self.total_pages > 0:
            return f" {self.pages_scanned}/{self.total_pages}"
        return ""
