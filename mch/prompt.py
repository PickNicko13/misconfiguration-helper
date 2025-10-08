import sys
from rich.console import Console
from rich.prompt import Prompt
from typing import List, Optional

console = Console()

# Conditional imports for platform-specific single-keypress input
if sys.platform == "win32":
    import msvcrt
else:
    import tty
    import termios

class SingleKeyPrompt:
    """A prompt that allows selecting an option with a single keypress, with automatic underlined letter selection."""
    
    def __init__(self, message: str, options: List[str], default: Optional[str] = None):
        """Initialize with prompt message, options, and optional default."""
        self.message = message
        self.options = options
        self.default = default if default in options else None
        self.key_map = self._assign_keys()
        self.console = console

    def _assign_keys(self) -> dict:
        """Assign unique keypress letters to each option, using the first unique letter."""
        key_map = {}
        used_keys = set()
        for option in self.options:
            for char in option.lower():
                if char.isalpha() and char not in used_keys:
                    key_map[char] = option
                    used_keys.add(char)
                    break
            else:
                raise ValueError(f"No unique letter available for option: {option}")
        return key_map

    def _render_prompt(self) -> str:
        """Render the prompt with underlined key letters."""
        formatted_options = []
        for option in self.options:
            key = next(k for k, v in self.key_map.items() if v == option)
            idx = option.lower().index(key)
            formatted_option = (
                option[:idx] +
                f"[underline]{option[idx]}[/underline]" +
                option[idx + 1:]
            )
            formatted_options.append(formatted_option)
        return f"{self.message} ({', '.join(formatted_options)})"

    def ask(self) -> str:
        """Capture a single keypress or fall back to text input, returning the selected option."""
        if sys.platform == "win32":
            self.console.print(self._render_prompt(), end=" ")
            while msvcrt.kbhit():
                msvcrt.getch()  # Clear buffer
            key = msvcrt.getch().decode('utf-8').lower()
            if key in self.key_map:
                selected = self.key_map[key]
                self.console.print(f"[green]{selected.replace('_', '-')}[/green]")
                return selected
            self.console.print("[red]Invalid key, please try again[/red]")
            return self.ask()

        elif sys.platform in ("linux", "darwin"):
            self.console.print(self._render_prompt(), end=" ", flush=True)
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setcbreak(fd)
                key = sys.stdin.read(1).lower()
                if key in self.key_map:
                    selected = self.key_map[key]
                    self.console.print(f"[green]{selected.replace('_', '-')}[/green]")
                    return selected
                self.console.print("[red]Invalid key, please try again[/red]")
                return self.ask()
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

        self.console.print("[yellow]Single-keypress input not available, using text input[/yellow]")
        return Prompt.ask(
            self._render_prompt(),
            choices=self.options,
            default=self.default
        )
