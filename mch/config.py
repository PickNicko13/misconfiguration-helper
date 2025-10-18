import tomli
import tomli_w
from pathlib import Path
from platformdirs import user_config_dir
from typing import Dict, Any
from mch.utils import setup_logging

DEFAULT_CONFIG = {
    "ports": {
        "range": "1-65535",
        "expected": [80, 443],  # Common expected ports; auto-ack on load
        "timeout": 1.0
    },
    "fuzz": {
        "wordlist": str(Path(__file__).parent / "wordlists" / "directory-list-2.3-small.txt"),
        "extensions": [],
        "timeout": 5.0,
        "delay": 0.0,
        "concurrency": 50
    },
    "acao": {
        "endpoints": ["/"],
        "malicious_origins": ["http://malicious-{domain}"],
        "timeout": 5.0
    }
}

class ConfigManager:
    def __init__(self):
        self.logger = setup_logging()
        self.config_dir = Path(user_config_dir("mch"))
        self.config_file = self.config_dir / "config.toml"
        self.config = self.load_config()

    def load_config(self) -> Dict[str, Any]:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        if not self.config_file.exists():
            self.logger.info(f"Config file not found at {self.config_file}. Creating from defaults.")
            self.save_config(DEFAULT_CONFIG)
        try:
            with open(self.config_file, "rb") as f:
                return tomli.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load config {self.config_file}: {e}")
            return DEFAULT_CONFIG

    def save_config(self, config: Dict[str, Any]):
        try:
            with open(self.config_file, "wb") as f:
                tomli_w.dump(config, f)
        except Exception as e:
            self.logger.error(f"Failed to save config {self.config_file}: {e}")

    def get(self, section: str, key: str, default: Any = None) -> Any:
        return self.config.get(section, {}).get(key, default)

    def merge_overrides(self, overrides: Dict[str, Any]):
        for section, values in overrides.items():
            if section in self.config:
                self.config[section].update(values)
            else:
                self.config[section] = values
