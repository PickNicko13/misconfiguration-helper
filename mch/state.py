import json
import os
from pathlib import Path
from platformdirs import user_data_dir
from typing import Dict, Any
from mch.utils import setup_logging
import hashlib

class StateManager:
    def __init__(self):
        self.logger = setup_logging()

        self.state_dir = Path(user_data_dir("mch")) / "targets"
        os.makedirs(self.state_dir, exist_ok=True)

    def _get_state_file(self, host: str) -> str:
        # Normalize host to avoid file system issues
        safe_host = hashlib.md5(host.encode()).hexdigest()
        return os.path.join(self.state_dir, f"{safe_host}.json")

    def load_state(self, host: str) -> Dict[str, Any]:
        state_file = self._get_state_file(host)
        default_state = {
            "ports": {"current_open": [], "acknowledged": []},
            "fuzz": {"issues": [], "will_fix": [], "false_positive": [], "wont_fix": []},
            "acao": {"issues": []}
        }
        try:
            if os.path.exists(state_file):
                with open(state_file, "r") as f:
                    state = json.load(f)
                    default_state.update(state)
                    self.logger.debug(f"Loaded state for {host}: {default_state}")
            else:
                self.logger.debug(f"No state file found for {host}, using default state")
        except Exception as e:
            self.logger.error(f"Failed to load state for {host}: {e}")
        return default_state

    def save_state(self, host: str, state: Dict[str, Any]):
        state_file = self._get_state_file(host)
        try:
            with open(state_file, "w") as f:
                json.dump(state, f, indent='\t')
            self.logger.debug(f"Saved state for {host} to {state_file}")
        except Exception as e:
            self.logger.error(f"Failed to save state for {host}: {e}")
