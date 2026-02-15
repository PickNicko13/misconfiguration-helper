"""Interactive single-keypress prompt system for MCH.

This module provides a specialized prompt class that allows users to acknowledge
scanner findings with a single key press, mapping characters to specific actions.
"""

import sys
from rich.console import Console
from rich.prompt import Prompt

#: Shared console instance for consistent prompting.
console = Console()

# Conditional imports for platform-specific single-keypress input
if sys.platform == 'win32':
	import msvcrt
else:
	import tty
	import termios


class SingleKeyPrompt:
	"""A prompt for selecting an option with a single keypress.

	This class automatically identifies unique letters in the provided options
	to use as keyboard shortcuts and handles platform-specific terminal locking.

	Attributes:
		message (str): The prompt message to display.
		options (List[str]): List of valid selection strings.
		default (Optional[str]): The fallback option if input is empty.
		key_map (Dict[str, str]): Mapping of keys to their respective options.
		console (Console): The rich console instance used for output.

	"""

	def __init__(self, message: str, options: list[str], default: str | None = None):
		"""Initialize the prompt with available choices.

		Args:
			message: The question or instruction for the user.
			options: A list of words to choose from.
			default: An optional default choice (must be in options).

		"""
		self.message = message
		self.options = options
		self.default = default if default in options else None
		self.key_map = self._assign_keys()
		self.console = console

	def _assign_keys(self) -> dict[str, str]:
		"""Identify and assign unique trigger keys for each option.

		Returns:
			Dict[str, str]: A dictionary of {character: option_name}.

		Raises:
			ValueError: If an option has no unique alphabetic characters left.

		"""
		key_map = {}
		used_keys = set()
		for option in self.options:
			for char in option.lower():
				if char.isalpha() and char not in used_keys:
					key_map[char] = option
					used_keys.add(char)
					break
			else:
				raise ValueError(f'No unique letter available for option: {option}')
		return key_map

	def _render_prompt(self) -> str:
		"""Generate the formatted prompt string with underlined shortcuts.

		Returns:
			str: A rich-formatted string for the console.

		"""
		formatted_options = []
		for option in self.options:
			key = next(k for k, v in self.key_map.items() if v == option)
			idx = option.lower().index(key)
			formatted_option = (
				option[:idx]
				+ f'[underline]{option[idx]}[/underline]'
				+ option[idx + 1 :]
			)
			formatted_options.append(formatted_option)
		return f'{self.message} ({", ".join(formatted_options)})'

	def ask(self) -> str:
		"""Capture a single keypress and return the corresponding option.

		Falls back to standard text input if the terminal is non-interactive
		or the platform is unsupported.

		Returns:
			str: The chosen option string.

		"""
		# Check if terminal supports rich markup
		if not sys.stdout.isatty():
			self.console.print(
				'[yellow]Non-interactive mode: using text input[/yellow]'
			)
			result = Prompt.ask(
				self.message, choices=self.options, default=self.default
			)
			if result is None:
				return self.ask()
			return result

		if sys.platform == 'win32':
			self.console.print(self._render_prompt(), end=' ')
			sys.stdout.flush()
			while msvcrt.kbhit():
				msvcrt.getch()  # Clear buffer
			key = msvcrt.getch().decode('utf-8').lower()
			if key in self.key_map:
				selected = self.key_map[key]
				self.console.print(f'[green]{selected.replace("_", "-")}[/green]')
				return selected
			self.console.print('[red]Invalid key, please try again[/red]')
			return self.ask()

		elif sys.platform in ('linux', 'darwin'):
			self.console.print(self._render_prompt(), end=' ')
			sys.stdout.flush()
			fd = sys.stdin.fileno()
			old_settings = termios.tcgetattr(fd)
			try:
				tty.setcbreak(fd)
				key = sys.stdin.read(1).lower()
				if key in self.key_map:
					selected = self.key_map[key]
					self.console.print(f'[green]{selected.replace("_", "-")}[/green]')
					return selected
				self.console.print('[red]Invalid key, please try again[/red]')
				return self.ask()
			finally:
				termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

		self.console.print(
			'[yellow]Single-keypress input not available, using text input[/yellow]'
		)
		result = Prompt.ask(
			self._render_prompt(), choices=self.options, default=self.default
		)
		if result is None:
			return self.ask()
		return result
