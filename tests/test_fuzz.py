import pytest
import respx
import httpx
from unittest.mock import MagicMock
from mch.scanners.fuzz import FuzzScanner
from mch.config import ConfigManager
from mch.state import StateManager


@pytest.fixture
def config(tmp_path):
    cfg = ConfigManager()
    wordlist_path = tmp_path / "wordlist.txt"
    wordlist_path.write_text("admin\nphpmyadmin\nbackup\n.env\nconfig\n")
    cfg.config = {
        "fuzz": {
            "wordlist": str(wordlist_path),
            "extensions": [".bak", ".old"],
            "timeout": 1.0,
            "delay": 0.0,
            "concurrency": 5
        }
    }
    return cfg


@pytest.fixture
def state_mgr(mocker):
    mgr = MagicMock(spec=StateManager)
    mgr.load_state.return_value = {
        "fuzz": {"issues": [], "false_positive": [], "wont_fix": []}
    }
    return mgr


@pytest.fixture
def scanner(config, state_mgr):
    return FuzzScanner(
        target="test.local",
        config=config,
        state_mgr=state_mgr,
        warn_html_errors=False
    )


ALL_PATHS = [
    "/admin", "/admin.bak", "/admin.old",
    "/phpmyadmin", "/phpmyadmin.bak", "/phpmyadmin.old",
    "/backup", "/backup.bak", "/backup.old",
    "/.env", "/.env.bak", "/.env.old",
    "/config", "/config.bak", "/config.old"
]


@pytest.mark.asyncio
@respx.mock
async def test_fuzz_finds_real_file(scanner):
    respx.head("http://test.local/").mock(return_value=httpx.Response(200))
    respx.head("https://test.local/").mock(return_value=httpx.Response(404))

    respx.get("http://test.local/admin").mock(return_value=httpx.Response(200))
    respx.get("http://test.local/admin.bak").mock(return_value=httpx.Response(200))

    for path in ALL_PATHS:
        if path not in ("/admin", "/admin.bak"):
            respx.get(f"http://test.local{path}").mock(return_value=httpx.Response(404))
        respx.get(f"https://test.local{path}").mock(return_value=httpx.Response(404))

    result = await scanner.run_async()

    found = result["found"]
    assert "http://test.local/admin" in found
    assert "http://test.local/admin.bak" in found
    assert len(found) == 2


@pytest.mark.asyncio
@respx.mock
async def test_fuzz_detects_redirects(scanner):
    respx.head("http://test.local/").mock(return_value=httpx.Response(200))
    respx.head("https://test.local/").mock(return_value=httpx.Response(404))

    respx.get("http://test.local/backup").mock(return_value=httpx.Response(301))
    respx.get("http://test.local/.env").mock(return_value=httpx.Response(302))

    for path in ALL_PATHS:
        if path not in ("/backup", "/.env"):
            respx.get(f"http://test.local{path}").mock(return_value=httpx.Response(404))
        respx.get(f"https://test.local{path}").mock(return_value=httpx.Response(404))

    result = await scanner.run_async()

    found = result["found"]
    assert "http://test.local/backup" in found
    assert "http://test.local/.env" in found


@pytest.mark.asyncio
@respx.mock
async def test_fuzz_ignores_fake_404_page(scanner):
    respx.head("http://test.local/").mock(return_value=httpx.Response(200))
    respx.head("https://test.local/").mock(return_value=httpx.Response(404))

    respx.get("http://test.local/config").mock(
        return_value=httpx.Response(200, text="Not Found - Page does not exist")
    )

    for path in ALL_PATHS:
        if path != "/config":
            respx.get(f"http://test.local{path}").mock(return_value=httpx.Response(404))
        respx.get(f"https://test.local{path}").mock(return_value=httpx.Response(404))

    result = await scanner.run_async()
    assert "/config" not in result["found"]


@pytest.mark.asyncio
@respx.mock
async def test_fuzz_skips_unavailable_scheme(scanner):
    respx.head("http://test.local/").mock(return_value=httpx.Response(200))
    respx.head("https://test.local/").mock(return_value=httpx.Response(404))

    respx.get("http://test.local/admin").mock(return_value=httpx.Response(200))

    for path in ALL_PATHS:
        if path != "/admin":
            respx.get(f"http://test.local{path}").mock(return_value=httpx.Response(404))
        respx.get(f"https://test.local{path}").mock(return_value=httpx.Response(404))

    result = await scanner.run_async()

    found = result["found"]
    assert len(found) == 1
    assert "http://test.local/admin" in found


@pytest.mark.asyncio
@respx.mock
async def test_fuzz_respects_concurrency_limit(scanner, mocker):
    semaphore_mock = mocker.patch("asyncio.Semaphore", autospec=True)
    semaphore_mock.return_value = mocker.AsyncMock()

    respx.head("http://test.local/").mock(return_value=httpx.Response(200))
    respx.head("https://test.local/").mock(return_value=httpx.Response(404))

    for path in ALL_PATHS:
        respx.get(f"http://test.local{path}").mock(return_value=httpx.Response(200 if "admin" in path else 404))
        respx.get(f"https://test.local{path}").mock(return_value=httpx.Response(404))

    await scanner.run_async()

    semaphore_mock.assert_called_once_with(5)


@pytest.mark.asyncio
@respx.mock
async def test_fuzz_saves_to_state(scanner):
    respx.head("http://test.local/").mock(return_value=httpx.Response(200))
    respx.head("https://test.local/").mock(return_value=httpx.Response(404))

    respx.get("http://test.local/admin").mock(return_value=httpx.Response(200))

    for path in ALL_PATHS:
        if path != "/admin":
            respx.get(f"http://test.local{path}").mock(return_value=httpx.Response(404))
        respx.get(f"https://test.local{path}").mock(return_value=httpx.Response(404))

    await scanner.run_async()

    assert "http://test.local/admin" in scanner.state["fuzz"]["issues"]
