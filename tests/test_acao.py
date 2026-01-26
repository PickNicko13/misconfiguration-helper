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
        "acao": {
            "endpoints": ["/", "/api", "/admin"],
            "malicious_origins": ["http://malicious-{domain}", "http://evil.com"],
            "timeout": 1.0
        }
    }
    return cfg


@pytest.fixture
def state_mgr(mocker):
    mgr = MagicMock(spec=StateManager)
    mgr.load_state.return_value = {"acao": {"issues": []}}
    return mgr


@pytest.fixture
def scanner(config, state_mgr):
    return AcaoScanner("test.local", config, state_mgr, False)


ENDPOINTS = ["/", "/api", "/admin"]
SCHEMES = ["http", "https"]


ORIGINS = [
    "http://test.local",
    "https://test.local",
    "http://malicious-test.local",
    "http://evil.com"
]


def mock_all_heads(respx_mock, acao_header: str, status=200):
    for scheme in SCHEMES:
        for endpoint in ENDPOINTS:
            url = f"{scheme}://test.local{endpoint}"
            for origin in ORIGINS:
                respx_mock.head(url).mock(
                    return_value=httpx.Response(status, headers={"Access-Control-Allow-Origin": acao_header})
                )


@pytest.mark.asyncio
@respx.mock
async def test_acao_arbitrary_origin(scanner):
    mock_all_heads(respx, "*")
    await scanner.run_async()

    issues = scanner.state["acao"]["issues"]
    star_issues = [i for i in issues if i["detail"] == "*"]
    assert len(star_issues) > 0
    assert len(star_issues) == 12  # 3 endpoints * 2 schemas * 2 origins


@pytest.mark.asyncio
@respx.mock
async def test_acao_leaked_ip(scanner):
    leaked_ip = "192.168.1.10"
    mock_all_heads(respx, f"http://{leaked_ip}")
    await scanner.run_async()

    issues = scanner.state["acao"]["issues"]
    ip_issues = [i for i in issues if leaked_ip in i["detail"]]
    assert len(ip_issues) > 0


@pytest.mark.asyncio
@respx.mock
async def test_acao_regex_vulnerable(scanner):
    regex = "http://.*.evil.com"
    mock_all_heads(respx, regex)
    await scanner.run_async()

    issues = scanner.state["acao"]["issues"]
    regex_issues = [i for i in issues if ".*" in i["detail"]]
    assert len(regex_issues) > 0


@pytest.mark.asyncio
@respx.mock
async def test_acao_safe_origin_does_not_add_issue(scanner):
    mock_all_heads(respx, "http://test.local")
    await scanner.run_async()

    issues = scanner.state["acao"]["issues"]
    assert len(issues) == 0


@pytest.mark.asyncio
@respx.mock
async def test_acao_multiple_endpoints(scanner):
    for scheme in ["http"]:
        for endpoint in ENDPOINTS:
            url = f"{scheme}://test.local{endpoint}"
            if endpoint == "/":
                acao = "*"
            elif endpoint == "/api":
                acao = "http://test.local"
            elif endpoint == "/admin":
                acao = "http://192.168.1.10"
            else:
                acao = "http://test.local"

            for origin in ORIGINS:
                respx.head(url).mock(
                    return_value=httpx.Response(200, headers={"Access-Control-Allow-Origin": acao})
                )

    for endpoint in ENDPOINTS:
        respx.head(f"https://test.local{endpoint}").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

    await scanner.run_async()

    issues = scanner.state["acao"]["issues"]
    assert len(issues) > 0, f"Очікував >0 issues, отримано {len(issues)}"

    arbitrary_on_root = [i for i in issues if i["endpoint"] == "/" and "*" in i["detail"]]
    assert len(arbitrary_on_root) > 0

    leaked_on_admin = [i for i in issues if i["endpoint"] == "/admin" and "192.168.1.10" in i["detail"]]
    assert len(leaked_on_admin) > 0


@pytest.mark.asyncio
@respx.mock
async def test_acao_probe_failure(scanner):
    for scheme in SCHEMES:
        for endpoint in ENDPOINTS:
            url = f"{scheme}://test.local{endpoint}"
            respx.head(url).mock(side_effect=httpx.ConnectError("Connection refused"))

    await scanner.run_async()

    assert len(scanner.state["acao"]["issues"]) == 0
