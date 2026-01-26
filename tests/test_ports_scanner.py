import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from mch.scanners.ports import PortScanner
from mch.config import ConfigManager
from mch.state import StateManager


@pytest.fixture
def config():
    cfg = ConfigManager()
    cfg.config = {
        "ports": {
            "range": "80-85",
            "timeout": 0.1,
            "expected": [80, 443]
        }
    }
    return cfg


@pytest.fixture
def state_mgr(mocker):
    mgr = MagicMock(spec=StateManager)
    mgr.load_state.return_value = {
        "ports": {
            "current_open": [],
            "acknowledged": [80]
        }
    }
    return mgr


@pytest.fixture
def scanner(config, state_mgr):
    return PortScanner(
        target="127.0.0.1",
        config=config,
        state_mgr=state_mgr,
        warn_html_errors=False
    )


@pytest.mark.asyncio
async def test_port_scanner_opens_port(scanner, mocker):
    open_connection_mock = AsyncMock()
    writer_mock = MagicMock()
    writer_mock.wait_closed = AsyncMock()
    open_connection_mock.return_value = (MagicMock(), writer_mock)
    mocker.patch("asyncio.open_connection", open_connection_mock)

    result = await scanner.run_async()

    assert sorted(result["new_ports"]) == [81, 82, 83, 84, 85]
    assert sorted(scanner.state["ports"]["current_open"]) == [80, 81, 82, 83, 84, 85]


@pytest.mark.asyncio
async def test_port_scanner_closed_port(scanner, mocker):
    open_connection_mock = AsyncMock(side_effect=ConnectionRefusedError)
    mocker.patch("asyncio.open_connection", open_connection_mock)

    result = await scanner.run_async()

    assert result["new_ports"] == []
    assert scanner.state["ports"]["current_open"] == []


@pytest.mark.asyncio
async def test_port_scanner_mixed_open_closed(scanner, mocker):
    async def mock_open(target, port, *args):
        if port in (82, 84):
            writer = MagicMock()
            writer.wait_closed = AsyncMock()
            return MagicMock(), writer
        raise ConnectionRefusedError

    mocker.patch("asyncio.open_connection", AsyncMock(side_effect=mock_open))

    result = await scanner.run_async()

    assert sorted(result["new_ports"]) == [82, 84]
    assert sorted(scanner.state["ports"]["current_open"]) == [82, 84]


@pytest.mark.asyncio
async def test_port_scanner_respects_acknowledged(scanner, mocker):
    scanner.state["ports"]["acknowledged"] = [80, 81, 82]

    async def mock_open(target, port, *args):
        if port in (83, 84, 85):
            writer = MagicMock()
            writer.wait_closed = AsyncMock()
            return MagicMock(), writer
        raise ConnectionRefusedError

    mocker.patch("asyncio.open_connection", AsyncMock(side_effect=mock_open))

    result = await scanner.run_async()

    assert sorted(result["new_ports"]) == [83, 84, 85]
    assert sorted(scanner.state["ports"]["current_open"]) == [83, 84, 85]


def test_port_scanner_total_ports_calculation(scanner):
    asyncio.run(scanner.run_async())
    assert scanner.total_ports == 6 # range 80-85
