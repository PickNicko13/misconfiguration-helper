"""Unit tests for the utility functions in the MCH project."""

import pytest
from typer import Exit
from mch.utils import validate_target


def test_validate_target_valid_ipv4():
	"""Ensure that valid IPv4 addresses are accepted as targets."""
	assert validate_target('192.168.1.1') == '192.168.1.1'


def test_validate_target_valid_domain():
	"""Ensure that valid domain names are accepted as targets."""
	assert validate_target('example.com') == 'example.com'


def test_validate_target_valid_url():
	"""Ensure that valid URLs are accepted as targets."""
	assert (
		validate_target('https://example.com:8443/path')
		== 'https://example.com:8443/path'
	)


def test_validate_target_invalid_type():
	"""Verify that providing an invalid data type as a target raises an Exit."""
	with pytest.raises(Exit):
		validate_target(123)


def test_validate_target_invalid_string():
	"""Verify that malformed target strings raise an Exit."""
	with pytest.raises(Exit):
		validate_target('invalid@host')


def test_validate_target_localhost():
	"""Ensure that 'localhost' is accepted as a valid target."""
	assert validate_target('localhost') == 'localhost'
