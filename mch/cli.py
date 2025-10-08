import typer
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn
from desktop_notifier import DesktopNotifier
from mch.config import ConfigManager
from mch.state import StateManager
from mch.utils import validate_target, setup_logging
from mch.prompt import SingleKeyPrompt
from mch.scanners import SCANNERS
from typing import List, Optional, Dict
import asyncio
import threading
import time
import re
import logging

app = typer.Typer()
console = Console()
notifier = DesktopNotifier(app_name="MCH")
logger = setup_logging()

async def send_notification(title: str, message: str):
    await notifier.send(title=title, message=message)

def run_async_in_thread(coro, scanner):
    """Run an async coroutine in a separate thread with its own event loop."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(coro)
    loop.close()
    scanner.run_result = result
    logger.debug(f"Async run completed for {scanner.__class__.__name__}: {result}")
    return result

@app.command()
def scan(
    types: str = typer.Argument("all", help="Comma-separated scan types (ports, fuzz, acao-leak, acao-weak) or 'all'"),
    hosts: Optional[List[str]] = typer.Argument(None, help="Hosts to scan"),
    host_list: Optional[typer.FileText] = typer.Option(None, "--host-list", help="File with hosts, one per line"),
    no_notify: bool = typer.Option(False, "--no-notify", help="Disable notifications"),
    warn_html_errors: bool = typer.Option(False, "--warn-html-errors", help="Warn on HTML errors"),
    overrides: Optional[List[str]] = typer.Option(None, "--override", help="Config overrides, e.g. ports.range=1-65535"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose debug output to console"),
):
    """Scan hosts for misconfigurations."""
    if verbose:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        logger.addHandler(console_handler)
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose mode enabled: Debug logs will be printed to console")

    config = ConfigManager()
    state_mgr = StateManager()
    if overrides:
        ov_dict = {}
        for ov in overrides:
            try:
                sec, key_val = ov.split(".", 1)
                key, val = key_val.split("=", 1)
                if sec not in ov_dict:
                    ov_dict[sec] = {}
                if sec == "ports" and key == "expected":
                    val = [int(x) for x in val.split(",") if x.strip()]
                elif sec in ("fuzz", "acao-leak", "acao-weak") and key in ("wordlist", "endpoints"):
                    val = val
                elif sec == "ports" and key == "range":
                    if not re.match(r"^\d+-\d+$", val):
                        raise ValueError(f"Invalid port range: {val}")
                    val = str(val)
                elif sec in ("fuzz", "acao-leak", "acao-weak") and key in ("timeout", "delay"):
                    val = float(val)
                elif sec in ("fuzz", "acao-leak", "acao-weak") and key in ("concurrency", "batch_size"):
                    val = int(val)
                else:
                    val = str(val)
                ov_dict[sec][key] = val
            except Exception as e:
                console.print(f"[red]Invalid override {ov}: {e}[/red]")
                logger.error(f"Invalid override {ov}: {e}")
                raise typer.Exit(1)
        config.merge_overrides(ov_dict)

    all_hosts = hosts or []
    if host_list:
        all_hosts += [line.strip() for line in host_list if line.strip()]
    if not all_hosts:
        console.print("[red]No hosts provided[/red]")
        logger.error("No hosts provided")
        raise typer.Exit(1)

    scan_types = SCANNERS.keys() if types == "all" else types.split(",")
    invalid_types = set(scan_types) - set(SCANNERS)
    if invalid_types:
        console.print(f"[red]Invalid scan types: {invalid_types}[/red]")
        logger.error(f"Invalid scan types: {invalid_types}")
        raise typer.Exit(1)

    progress = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console)
    with Live(progress, refresh_per_second=50) as live:
        tasks = {host: progress.add_task(f"{host}: waiting", total=len(scan_types)) for host in all_hosts}
        for host in all_hosts:
            logger.debug(f"Processing host: {host} (type: {type(host)})")
            validated_host = validate_target(host)
            logger.debug(f"Validated host: {validated_host} (type: {type(validated_host)})")
            status = {t: {"state": "waiting", "progress": ""} for t in scan_types}
            errors = []
            warnings = 0
            for t in scan_types:
                status[t]["state"] = "scanning"
                logger.debug(f"Initial status update for {t} on {host}: scanning")
                update_status(progress, tasks, host, status, warnings, len(errors))
                try:
                    scanner = SCANNERS[t](validated_host, config, state_mgr, warn_html_errors)
                    logger.debug(f"Scanner for {t}: {scanner.__class__.__name__}")
                    if t in ["ports", "fuzz", "acao-weak"]:
                        logger.debug(f"Starting async scan for {t} on {host}")
                        thread = threading.Thread(target=run_async_in_thread, args=(scanner.run(), scanner))
                        thread.start()
                        last_progress = ""
                        while thread.is_alive() or (hasattr(scanner, "is_scanning") and scanner.is_scanning()):
                            progress_str = scanner.get_progress() if hasattr(scanner, "get_progress") else ""
                            if progress_str != last_progress:
                                status[t]["progress"] = progress_str
                                logger.debug(f"Progress update for {t} on {host}: {progress_str}")
                                update_status(progress, tasks, host, status, warnings, len(errors))
                                live.refresh()
                                last_progress = progress_str
                            time.sleep(0.005)
                        thread.join()
                        res = scanner.run_result
                        logger.debug(f"Async scan {t} result: {res}")
                        if res:
                            warnings += sum(len(v) for v in res.values() if v)
                    else:
                        logger.debug(f"Starting sync scan for {t} on {host}")
                        res = scanner.run()
                        logger.debug(f"Sync scan {t} result: {res}")
                        if res:
                            warnings += sum(len(v) for v in res.values() if v)
                    status[t]["progress"] = scanner.get_progress() if hasattr(scanner, "get_progress") else ""
                    status[t]["state"] = "complete"
                    logger.debug(f"Final status update for {t} on {host}: complete, warnings={warnings}")
                    update_status(progress, tasks, host, status, warnings, len(errors))
                except Exception as e:
                    errors.append(f"{t}: {e}")
                    console.print(f"[red]Error in {t} on {host}: {e}[/red]")
                    logger.error(f"Error in {t} on {host}: {e}")
                    status[t]["state"] = "error"
                    logger.debug(f"Error status update for {t} on {host}: error")
                    update_status(progress, tasks, host, status, warnings, len(errors))
                progress.update(tasks[host], advance=1)
                live.refresh()
                time.sleep(0.1)

    if not no_notify:
        logger.debug("Sending scan completion notification")
        asyncio.run(send_notification(title="MCH Scan Complete", message=f"Scanned {len(all_hosts)} hosts."))

def update_status(progress: Progress, tasks: Dict, host: str, status: Dict, warnings: int, errors: int):
    desc = f"{host}: " + ", ".join([f"{t} ({s['state']}{s['progress']})" for t, s in status.items()])
    desc += f" [[yellow]{warnings}[/yellow]/[red]{errors}[/red]]"
    logger.debug(f"Updating status display: {desc}")
    progress.update(tasks[host], description=desc)

@app.command()
def report(
    hosts: List[str] = typer.Argument(..., help="Hosts to report"),
    type: str = typer.Option("warnings", "--type", help="critical, warnings (default), all"),
):
    """Report scan results."""
    state_mgr = StateManager()
    for host in hosts:
        state = state_mgr.load_state(host)
        logger.debug(f"Loaded state for {host}: {state.get('ports', {})}")
        table = Table(title=f"Report for {host} ({type})")
        table.add_column("Type")
        table.add_column("Issues")
        if type == "critical":
            acao_leak_issues = [k for k, v in state.get("acao-leak", {}).get("issues", {}).items() if v == "uncategorized"]
            acao_weak_issues = [k for k, v in state.get("acao-weak", {}).get("issues", {}).items() if v == "uncategorized"]
            table.add_row("ACAO Leaks", f"[red]{len(acao_leak_issues)} leaks[/red]" if acao_leak_issues else "None")
            table.add_row("ACAO Weak Regex", f"[red]{len(acao_weak_issues)} issues[/red]" if acao_weak_issues else "None")
        elif type == "warnings":
            new_ports = [p for p in state["ports"].get("current_open", []) if p not in state["ports"].get("acknowledged", [])]
            fuzz_issues = [p for p in state["fuzz"].get("issues", []) if p not in state["fuzz"].get("will_fix", []) + state["fuzz"].get("false_positive", []) + state["fuzz"].get("wont_fix", [])]
            acao_leak_issues = [k for k, v in state.get("acao-leak", {}).get("issues", {}).items() if v == "uncategorized"]
            acao_weak_issues = [k for k, v in state.get("acao-weak", {}).get("issues", {}).items() if v == "uncategorized"]
            table.add_row("Unacked Ports", f"[yellow]{new_ports}[/yellow]" if new_ports else "None")
            table.add_row("Fuzz Issues", f"[yellow]{len(fuzz_issues)} found[/yellow]" if fuzz_issues else "None")
            table.add_row("ACAO Leak Issues", f"[yellow]{len(acao_leak_issues)} issues[/yellow]" if acao_leak_issues else "None")
            table.add_row("ACAO Weak Regex Issues", f"[yellow]{len(acao_weak_issues)} issues[/yellow]" if acao_weak_issues else "None")
        elif type == "all":
            table.add_row("All Ports", str(list(state["ports"].get("current_open", []))))
            table.add_row("Port Statuses", str({
                "current_open": state["ports"].get("current_open", []),
                "acknowledged": state["ports"].get("acknowledged", [])
            }))
            table.add_row("Fuzz Issues", str(list(state["fuzz"].get("issues", []))))
            table.add_row("Fuzz Statuses", str({
                "issues": state["fuzz"].get("issues", []),
                "will_fix": state["fuzz"].get("will_fix", []),
                "false_positive": state["fuzz"].get("false_positive", []),
                "wont_fix": state["fuzz"].get("wont_fix", [])
            }))
            table.add_row("ACAO Leak Issues", str(list(state["acao-leak"].get("issues", {}).keys())))
            table.add_row("ACAO Leak Statuses", str({k: v for k, v in state.get("acao-leak", {}).get("issues", {}).items()}))
            table.add_row("ACAO Weak Regex Issues", str(list(state["acao-weak"].get("issues", {}).keys())))
            table.add_row("ACAO Weak Regex Statuses", str({k: v for k, v in state.get("acao-weak", {}).get("issues", {}).items()}))
        console.print(table)

@app.command()
def ack(host: str = typer.Argument(..., help="Host to acknowledge issues")):
    """Interactively acknowledge issues."""
    state_mgr = StateManager()
    state = state_mgr.load_state(host)

    new_ports = [p for p in state["ports"].get("current_open", []) if p not in state["ports"].get("acknowledged", [])]
    for port in new_ports:
        prompt = SingleKeyPrompt(
            message=f"Acknowledge port {port} on {host}",
            options=["acknowledge", "skip"],
            default="skip"
        )
        response = prompt.ask()
        if response == "acknowledge":
            state["ports"]["acknowledged"].append(port)
            console.print(f"[green]Acknowledged port {port} on {host}[/green]")

    fuzz_issues = [p for p in state["fuzz"].get("issues", []) if p not in state["fuzz"].get("will_fix", []) + state["fuzz"].get("false_positive", []) + state["fuzz"].get("wont_fix", [])]
    for path in fuzz_issues:
        prompt = SingleKeyPrompt(
            message=f"Acknowledge fuzz issue {path} on {host}",
            options=["will_fix", "false_positive", "wont_fix", "skip"],
            default="skip"
        )
        response = prompt.ask()
        if response in ["will_fix", "false_positive", "wont_fix"]:
            state["fuzz"]["issues"].remove(path)
            state["fuzz"].setdefault(response, []).append(path)
            console.print(f"[green]Marked {path} as {response.replace('_', '-')}[/green]")

    acao_leak_issues = [k for k, v in state.get("acao-leak", {}).get("issues", {}).items() if v == "uncategorized"]
    for issue in acao_leak_issues:
        prompt = SingleKeyPrompt(
            message=f"Acknowledge ACAO leak issue {issue} on {host}",
            options=["will_fix", "false_positive", "wont_fix", "skip"],
            default="skip"
        )
        response = prompt.ask()
        if response in ["will_fix", "false_positive", "wont_fix"]:
            state["acao-leak"]["issues"][issue] = response
            console.print(f"[green]Marked {issue} as {response.replace('_', '-')}[/green]")

    acao_weak_issues = [k for k, v in state.get("acao-weak", {}).get("issues", {}).items() if v == "uncategorized"]
    for issue in acao_weak_issues:
        prompt = SingleKeyPrompt(
            message=f"Acknowledge ACAO weak issue {issue} on {host}",
            options=["will_fix", "false_positive", "wont_fix", "skip"],
            default="skip"
        )
        response = prompt.ask()
        if response in ["will_fix", "false_positive", "wont_fix"]:
            state["acao-weak"]["issues"][issue] = response
            console.print(f"[green]Marked {issue} as {response.replace('_', '-')}[/green]")

    state_mgr.save_state(host, state)

def main():
    app()

if __name__ == "__main__":
    main()
