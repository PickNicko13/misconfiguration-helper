import pytest
from typer import Exit
from mch.utils import validate_target


def test_validate_target_valid_ipv4():
	assert validate_target('192.168.1.1') == '192.168.1.1'


def test_validate_target_valid_domain():
	assert validate_target('example.com') == 'example.com'


def test_validate_target_valid_url():
	assert (
		validate_target('https://example.com:8443/path')
		== 'https://example.com:8443/path'
	)


def test_validate_target_invalid_type():
	with pytest.raises(Exit):
		validate_target(123)


def test_validate_target_invalid_string():
	with pytest.raises(Exit):
		validate_target('invalid@host')


def test_validate_target_localhost():
	assert validate_target('localhost') == 'localhost'
