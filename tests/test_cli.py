import pytest
from rich.progress import Progress, TaskID
from mch.cli import update_status, parse_overrides


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
