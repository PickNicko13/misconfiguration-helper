"""Unit tests for the SingleKeyPrompt in the MCH project."""

import pytest
from mch.prompt import SingleKeyPrompt


def test_assign_keys_unique_letters():
	"""Test that keys are uniquely assigned to options."""
	prompt = SingleKeyPrompt(
		message='Choose action',
		options=['acknowledge', 'false_positive', 'wont_fix', 'skip'],
	)
	key_map = prompt.key_map

	assert len(key_map) == 4
	assert set(key_map.values()) == {
		'acknowledge',
		'false_positive',
		'wont_fix',
		'skip',
	}
	used_letters = set(key_map.keys())
	assert len(used_letters) == 4


def test_assign_keys_uses_first_unique_letter():
	"""Ensure that the first available unique letter in an option is used as its key."""
	prompt = SingleKeyPrompt(message='Test', options=['save', 'skip', 'show'])
	key_map = prompt.key_map

	assert key_map['s'] == 'save'  # s for save
	assert key_map['k'] == 'skip'  # k for skip (s already taken)
	assert key_map['h'] == 'show'  # h for show


def test_assign_keys_raises_when_no_unique_letter():
	"""Verify that a ValueError is raised if no unique letters can be assigned."""
	with pytest.raises(ValueError, match='No unique letter available for option'):
		SingleKeyPrompt(message='Conflict', options=['aa', 'ab', 'bb'])


def test_render_prompt_underlines_correct_letter():
	"""Test that the rendered prompt correctly underlines the shortcut keys."""
	prompt = SingleKeyPrompt(message='Select', options=['acknowledge', 'skip'])
	rendered = prompt._render_prompt()

	assert '[underline]a[/underline]' in rendered  # *A*cknowledge
	assert '[underline]s[/underline]' in rendered  # *S*kip
