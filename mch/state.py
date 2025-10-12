import json
from pathlib import Path
from platformdirs import user_data_dir
from typing import Dict, Any
from mch.utils import setup_logging

class StateManager:
    def __init__(self):
        self.logger = setup_logging()
        self.data_dir = Path(user_data_dir("mch")) / "targets"
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def get_state_file(self, target: str) -> Path:
        sanitized = target.replace("/", "_").replace(":", "_").replace(".", "_")
        return self.data_dir / f"{sanitized}.json"

    def load_state(self, target: str) -> Dict[str, Any]:
        state_file = self.get_state_file(target)
        if state_file.exists():
            try:
                with open(state_file, "r") as f:
                    state = json.load(f)
                    # Auto-ack expected ports from config on load
                    from mch.config import ConfigManager
                    config = ConfigManager()
                    expected = config.get("ports", "expected", [])
                    if "ports" in state:
                        state["ports"].setdefault("acknowledged", []).extend([p for p in expected if p not in state["ports"]["acknowledged"]])
                    return state
            except Exception as e:
                self.logger.error(f"Failed to load state {state_file}: {e}")
                return self._default_state()
        return self._default_state()

    def _default_state(self) -> Dict[str, Any]:
        return {
            "ports": {"acknowledged": [], "current_open": []},
            "fuzz": {"issues": [], "will_fix": [], "false_positive": [], "wont_fix": []},
            "acao-leak": {"issues": {}},
            "acao-weak": {"issues": {}},
        }

    def save_state(self, target: str, state: Dict[str, Any]):
        state_file = self.get_state_file(target)
        try:
            with open(state_file, "w") as f:
                json.dump(state, f, indent=4)
        except Exception as e:
            self.logger.error(f"Failed to save state {state_file}: {e}")
