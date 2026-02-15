"""Unit tests for the ConfigManager in the MCH project."""

import pytest
from mch.config import ConfigManager


@pytest.fixture
def config():
	"""Provide a ConfigManager instance for testing."""
	return ConfigManager()


def test_merge_overrides_simple_update(config):
	"""Test simple updates to existing configuration sections."""
	overrides = {'ports': {'timeout': '2.5'}}
	config.merge_overrides(overrides)
	assert config.get('ports', 'timeout') == '2.5'


def test_merge_overrides_list_as_is(config):
	"""Ensure that list-based overrides are preserved correctly."""
	overrides = {'ports': {'expected': [22, 2222]}}
	config.merge_overrides(overrides)
	assert config.get('ports', 'expected') == [22, 2222]


def test_merge_overrides_new_section(config):
	"""Test adding a brand-new section via overrides."""
	overrides = {'newsec': {'key': 'value'}}
	config.merge_overrides(overrides)
	assert config.get('newsec', 'key') == 'value'


def test_merge_overrides_overwrite_existing(config):
	"""Verify that overrides correctly overwrite existing configuration values."""
	assert config.get('ports', 'timeout') == 1.0

	overrides = {'ports': {'timeout': '3.0'}}
	config.merge_overrides(overrides)
	assert config.get('ports', 'timeout') == '3.0'


def test_merge_overrides_multiple_sections(config):
	"""Test merging overrides into multiple sections simultaneously."""
	overrides = {'ports': {'timeout': '0.8'}, 'fuzz': {'concurrency': '200'}}
	config.merge_overrides(overrides)
	assert config.get('ports', 'timeout') == '0.8'
	assert config.get('fuzz', 'concurrency') == '200'
