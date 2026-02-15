import pytest
import respx
import httpx
from unittest.mock import MagicMock
from mch.scanners.acao import AcaoScanner
from mch.config import ConfigManager
from mch.state import StateManager


@pytest.fixture
def config():
	cfg = ConfigManager()
	cfg.config = {
		'acao': {
			'endpoints': ['/', '/api', '/admin'],
			'malicious_origins': ['http://malicious-{domain}', 'http://evil.com'],
			'timeout': 1.0,
		}
	}
	return cfg


@pytest.fixture
def state_mgr(mocker):
	mgr = MagicMock(spec=StateManager)
	mgr.load_state.return_value = {'acao': {'issues': []}}
	return mgr


@pytest.fixture
def scanner(config, state_mgr):
	return AcaoScanner('test.local', config, state_mgr, False)


ENDPOINTS = ['/', '/api', '/admin']
SCHEMES = ['http', 'https']


ORIGINS = [
	'http://test.local',
	'https://test.local',
	'http://malicious-test.local',
	'http://evil.com',
]


def mock_all_heads(respx_mock, acao_header: str, status=200):
	for scheme in SCHEMES:
		for endpoint in ENDPOINTS:
			url = f'{scheme}://test.local{endpoint}'
			for origin in ORIGINS:
				respx_mock.head(url).mock(
					return_value=httpx.Response(
						status, headers={'Access-Control-Allow-Origin': acao_header}
					)
				)


@pytest.mark.asyncio
@respx.mock
async def test_acao_arbitrary_origin(scanner):
	mock_all_heads(respx, '*')
	await scanner.run_async()

	issues = scanner.state['acao']['issues']
	star_issues = [i for i in issues if i['detail'] == '*']

	expected_count = 3 * 2  # 3 endpoints * 2 schemas
	assert len(star_issues) == expected_count


@pytest.mark.asyncio
@respx.mock
async def test_acao_leaked_ip(scanner):
	leaked_ip = '192.168.1.10'
	mock_all_heads(respx, f'http://{leaked_ip}')
	await scanner.run_async()

	issues = scanner.state['acao']['issues']
	ip_issues = [i for i in issues if leaked_ip in i['detail']]
	assert len(ip_issues) > 0


@pytest.mark.asyncio
@respx.mock
async def test_acao_regex_vulnerable(scanner):
	regex = 'http://.*.evil.com'
	mock_all_heads(respx, regex)
	await scanner.run_async()

	issues = scanner.state['acao']['issues']
	regex_issues = [i for i in issues if '.*' in i['detail']]
	assert len(regex_issues) > 0


@pytest.mark.asyncio
@respx.mock
async def test_acao_safe_origin_does_not_add_issue(scanner):
	mock_all_heads(respx, 'http://test.local')
	await scanner.run_async()

	issues = scanner.state['acao']['issues']
	assert len(issues) == 0


@pytest.mark.asyncio
@respx.mock
async def test_acao_multiple_endpoints(scanner):
	for scheme in ['http']:
		for endpoint in ENDPOINTS:
			url = f'{scheme}://test.local{endpoint}'
			if endpoint == '/':
				acao = '*'
			elif endpoint == '/api':
				acao = 'http://test.local'
			elif endpoint == '/admin':
				acao = 'http://192.168.1.10'
			else:
				acao = 'http://test.local'

			for origin in ORIGINS:
				respx.head(url).mock(
					return_value=httpx.Response(
						200, headers={'Access-Control-Allow-Origin': acao}
					)
				)

	for endpoint in ENDPOINTS:
		respx.head(f'https://test.local{endpoint}').mock(
			side_effect=httpx.ConnectError('Connection refused')
		)

	await scanner.run_async()

	issues = scanner.state['acao']['issues']
	assert len(issues) > 0, f'Очікував >0 issues, отримано {len(issues)}'

	arbitrary_on_root = [
		i for i in issues if i['endpoint'] == '/' and '*' in i['detail']
	]
	assert len(arbitrary_on_root) > 0

	leaked_on_admin = [
		i for i in issues if i['endpoint'] == '/admin' and '192.168.1.10' in i['detail']
	]
	assert len(leaked_on_admin) > 0


@pytest.mark.asyncio
@respx.mock
async def test_acao_probe_failure(scanner):
	for scheme in SCHEMES:
		for endpoint in ENDPOINTS:
			url = f'{scheme}://test.local{endpoint}'
			respx.head(url).mock(side_effect=httpx.ConnectError('Connection refused'))

	await scanner.run_async()

	assert len(scanner.state['acao']['issues']) == 0


@pytest.mark.asyncio
@respx.mock
async def test_acao_leaked_domain_on_own_origin(scanner):
	"""Перевірка, що при власному origin і ACAO != власний домен — додається leaked_domain"""
	mock_all_heads(respx, 'http://internal.secret.com')  # не збігається з test.local

	await scanner.run_async()

	issues = scanner.state['acao']['issues']
	leaked_issues = [i for i in issues if i['weak_type'] == 'leaked_domain']
	assert len(leaked_issues) > 0
	assert 'internal.secret.com' in leaked_issues[0]['detail']


@pytest.mark.asyncio
@respx.mock
async def test_acao_arbitrary_from_malicious_origin(scanner):
	respx.head('http://test.local/').mock(
		return_value=httpx.Response(
			200, headers={'Access-Control-Allow-Origin': 'http://evil.com'}
		)
	)
	for scheme in SCHEMES:
		for endpoint in ENDPOINTS:
			if scheme == 'http' and endpoint == '/':
				continue
			respx.head(f'{scheme}://test.local{endpoint}').mock(
				side_effect=httpx.ConnectError('fallback')
			)

	await scanner.run_async()

	issues = scanner.state['acao']['issues']
	arbitrary_issues = [i for i in issues if i['weak_type'] == 'arbitrary']
	assert len(arbitrary_issues) > 0
	assert arbitrary_issues[0]['detail'] == 'http://evil.com'


@pytest.mark.asyncio
@respx.mock
async def test_acao_broad_reflection(scanner):
	acao = 'example.com'
	crafted = 'http://evil-example.com'

	for origin in ORIGINS:
		respx.head('http://test.local/').mock(
			return_value=httpx.Response(
				200, headers={'Access-Control-Allow-Origin': acao}
			)
		)

	respx.head('http://test.local/').mock(
		return_value=httpx.Response(200, headers={'Access-Control-Allow-Origin': acao})
	)

	for scheme in SCHEMES:
		for endpoint in ['/api', '/admin']:
			respx.head(f'{scheme}://test.local{endpoint}').mock(
				side_effect=httpx.ConnectError('fallback')
			)
	respx.head('https://test.local/').mock(side_effect=httpx.ConnectError('fallback'))

	await scanner.run_async()

	issues = scanner.state['acao']['issues']
	broad_issues = [i for i in issues if i['weak_type'] == 'broad-reflection']
	assert len(broad_issues) > 0
	assert f'vulnerable to {crafted}' in broad_issues[0]['detail']


@pytest.mark.asyncio
@respx.mock
async def test_acao_state_persistence_and_status_change(mocker):
	config = ConfigManager()
	config.config = {
		'acao': {
			'endpoints': ['/', '/api', '/admin'],
			'malicious_origins': ['http://malicious-{domain}', 'http://evil.com'],
			'timeout': 1.0,
		}
	}
	state_mgr = MagicMock(spec=StateManager)

	initial_issue = {
		'scheme': 'http',
		'hostname': 'test.local',
		'endpoint': '/',
		'weak_type': 'arbitrary',
		'detail': '*',
		'status': 'uncategorized',
	}
	initial_state = {'acao': {'issues': [initial_issue.copy()]}}
	mocker.patch.object(state_mgr, 'load_state', return_value=initial_state)

	scanner = AcaoScanner('test.local', config, state_mgr, False)

	mock_all_heads(respx, 'http://test.local')

	await scanner.run_async()

	issues = scanner.state['acao']['issues']
	assert len(issues) == 1
	assert issues[0]['status'] == 'resolved'
	assert issues[0]['detail'] == '*'


@pytest.mark.asyncio
@respx.mock
async def test_acao_handle_issue_existing_uncategorized(scanner):
	existing = {
		'scheme': 'http',
		'hostname': 'test.local',
		'endpoint': '/',
		'weak_type': 'arbitrary',
		'detail': '*',
		'status': 'uncategorized',
	}
	scanner.state['acao']['issues'] = [existing]

	issue = existing.copy()

	handled = scanner._handle_issue(
		issue, scanner.state['acao']['issues'], 'http://test.local/', '*', '*'
	)
	assert handled is None
