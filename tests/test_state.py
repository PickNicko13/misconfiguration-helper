"""Unit tests for the StateManager in the MCH project."""

import pytest
import hashlib
from pathlib import Path
from mch.state import StateManager


@pytest.fixture
def state_mgr(tmp_path):
	"""Provide a StateManager instance with a temporary directory for tests."""
	mgr = StateManager()
	mgr.state_dir = tmp_path / 'targets'
	mgr.state_dir.mkdir()
	return mgr


def test_get_state_file_generates_md5(state_mgr):
	"""Verify that state filenames are correctly generated using MD5 hashes."""
	host = 'example.com'
	expected_hash = hashlib.md5(host.encode()).hexdigest()
	expected_filename = f'{expected_hash}.json'

	path = state_mgr._get_state_file(host)
	assert Path(path).name == expected_filename


def test_get_state_file_handles_special_chars(state_mgr):
	"""Ensure that state file generation handles special characters in hostnames."""
	host = 'test@host:8080/with/path'
	expected_hash = hashlib.md5(host.encode()).hexdigest()
	path = state_mgr._get_state_file(host)
	assert Path(path).name == f'{expected_hash}.json'


def test_load_state_returns_default_when_no_file(state_mgr):
	"""Test that load_state returns a default empty state if no file exists."""
	state = state_mgr.load_state('nonexistent.local')

	assert 'ports' in state
	assert 'current_open' in state['ports']
	assert state['ports']['current_open'] == []
	assert state['ports']['acknowledged'] == []

	assert 'fuzz' in state
	assert state['fuzz']['issues'] == []

	assert 'acao' in state
	assert state['acao']['issues'] == []


def test_save_and_load_state_roundtrip(state_mgr):
	"""Verify that saving and then loading a state preserves all details correctly."""
	host = 'test.local'
	original_state = {
		'ports': {'current_open': [80, 443, 8080], 'acknowledged': [80, 443]},
		'fuzz': {
			'issues': ['/admin/', '/.env', '/backup.sql'],
			'false_positive': ['/test.txt'],
		},
		'acao': {
			'issues': [
				{
					'scheme': 'https',
					'hostname': 'test.local',
					'endpoint': '/',
					'weak_type': 'arbitrary',
					'status': 'uncategorized',
				}
			]
		},
	}

	state_mgr.save_state(host, original_state)
	loaded = state_mgr.load_state(host)

	assert loaded == original_state
