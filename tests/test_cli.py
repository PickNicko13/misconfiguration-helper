import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from rich.progress import Progress
from mch.cli import app, parse_overrides, update_status

runner = CliRunner()

def test_update_status_formats_all_scanners():
    progress = Progress()
    task_id = progress.add_task("test", total=3)
    tasks = {"example.com": task_id}

    status = {
        "ports": {"state": "complete", "progress": " 5/10"},
        "fuzz": {"state": "scanning", "progress": " 42/100"},
        "acao": {"state": "error", "progress": ""}
    }

    update_status(progress, tasks, "example.com", status, warnings=3, errors=1)

    desc = progress.tasks[task_id].description
    assert "example.com:" in desc
    assert "ports (complete 5/10)" in desc
    assert "fuzz (scanning 42/100)" in desc
    assert "acao (error)" in desc
    assert "[yellow]3[/yellow]/[red]1[/red]" in desc


def test_update_status_empty_status():
    progress = Progress()
    task_id = progress.add_task("test", total=0)
    tasks = {"localhost": task_id}

    status = {}
    update_status(progress, tasks, "localhost", status, warnings=0, errors=0)

    desc = progress.tasks[task_id].description
    assert "localhost:" in desc
    assert "[]" not in desc
    assert "[[yellow]0[/yellow]/[red]0[/red]]" in desc

def test_parse_ports_expected():
    overrides = ["ports.expected=80,443,22"]
    result = parse_overrides(overrides)
    assert result == {"ports": {"expected": [80, 443, 22]}}

def test_parse_invalid_range_raises():
    overrides = ["ports.range=abc"]
    with pytest.raises(ValueError, match="Invalid port range: abc"):
        parse_overrides(overrides)


def test_parse_overrides_ports_expected():
    overrides = ["ports.expected=80,443,22"]
    result = parse_overrides(overrides)
    assert result == {"ports": {"expected": [80, 443, 22]}}


def test_parse_overrides_fuzz_wordlist():
    overrides = ["fuzz.wordlist=/tmp/custom.txt,/tmp/extra.txt"]
    result = parse_overrides(overrides)
    assert result == {"fuzz": {"wordlist": ["/tmp/custom.txt", "/tmp/extra.txt"]}}


def test_parse_overports_range():
    overrides = ["ports.range=1000-2000"]
    result = parse_overrides(overrides)
    assert result == {"ports": {"range": "1000-2000"}}

def test_parse_multiple_sections():
    overrides = ["ports.timeout=2.5", "fuzz.concurrency=100"]
    result = parse_overrides(overrides)
    assert result == {
        "ports": {"timeout": "2.5"},
        "fuzz": {"concurrency": 100}
    }

@patch("mch.cli.asyncio.run")
@patch("mch.cli.ConfigManager")
@patch("mch.cli.StateManager")
def test_scan_all_types(mock_state_mgr, mock_config, mock_asyncio_run):
    mock_config.return_value = MagicMock()
    mock_state_mgr.return_value = MagicMock()

    result = runner.invoke(app, ["scan", "all", "test.local"])

    assert result.exit_code == 0
    mock_asyncio_run.assert_called_once()


@patch("mch.cli.asyncio.run")
def test_scan_with_override(mock_asyncio_run):
    result = runner.invoke(
        app,
        ["scan", "ports", "test.local", "--override", "ports.range=80-90"]
    )

    assert result.exit_code == 0
    mock_asyncio_run.assert_called_once()


def test_scan_no_hosts():
    result = runner.invoke(app, ["scan", "all"])
    assert result.exit_code != 0
    assert "No hosts provided" in result.stdout


@patch("mch.cli.StateManager")
def test_report_warnings(mock_state_mgr):
    mock_state = {
        "ports": {"current_open": [80, 8080], "acknowledged": [80]},
        "fuzz": {"issues": ["/admin"], "will_fix": []},
        "acao": {
            "issues": [
                {
                    "scheme": "https",
                    "hostname": "test.local",
                    "endpoint": "/api",
                    "weak_type": "regex",
                    "detail": "http://test.local",
                    "status": "uncategorized"
                }
            ]
        }
    }
    mock_state_mgr.return_value.load_state.return_value = mock_state

    result = runner.invoke(app, ["report", "test.local", "--type", "warnings"])

    assert result.exit_code == 0
    assert "Unacked Ports" in result.stdout
    assert "Fuzz Issues" in result.stdout
    assert "ACAO Issues" in result.stdout

@patch("mch.cli.StateManager")
def test_report_warnings_handles_broken_acao_issue(mock_state_mgr):
    mock_state = {
        "ports": {"current_open": [], "acknowledged": []},
        "fuzz": {"issues": []},
        "acao": {"issues": [{"status": "uncategorized"}]}  # Intentionally broken
    }
    mock_state_mgr.return_value.load_state.return_value = mock_state

    result = runner.invoke(app, ["report", "test.local", "--type", "warnings"])

    assert result.exit_code == 1 # should fail, so 1


@patch("mch.cli.sys.stdout.isatty")
@patch("mch.cli.StateManager")
def test_ack_non_tty_mode(mock_state_mgr, mock_isatty):
    mock_isatty.return_value = False  # non-interactive mode
    mock_state = {"ports": {"current_open": [8080], "acknowledged": []}}
    mock_state_mgr.return_value.load_state.return_value = mock_state

    result = runner.invoke(app, ["ack", "test.local"])

    assert result.exit_code == 0
    assert "Acknowledging issues for test.local (plain text mode)" in result.stdout
