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
import sys
from rich.logging import RichHandler

app = typer.Typer()
console = Console()
notifier = DesktopNotifier(app_name="MCH")
logger = setup_logging()

async def send_notification(title: str, message: str):
    await notifier.send(title=title, message=message)

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
        # Clear existing stream handlers to avoid duplicates
        existing_handlers = [h for h in logger.handlers if isinstance(h, logging.StreamHandler) or isinstance(h, RichHandler)]
        for h in existing_handlers:
            logger.removeHandler(h)
        # Use RichHandler for verbose (DEBUG) console output to integrate with Live and enable proper formatting/coloration
        console_handler = RichHandler(level=logging.DEBUG, show_time=False, show_level=True, show_path=False, markup=True)
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
                elif sec == "fuzz" and key == "wordlist":
                    val = [x.strip() for x in val.split(",") if x.strip()]
                elif sec in ("fuzz", "acao-leak", "acao-weak") and key in ("endpoints", "malicious_origins"):
                    val = [x.strip() for x in val.split(",") if x.strip()]
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

    # Run the async scan
    asyncio.run(async_scan(all_hosts, scan_types, config, state_mgr, warn_html_errors, no_notify, verbose))

async def async_scan(all_hosts: List[str], scan_types: List[str], config: ConfigManager, state_mgr: StateManager, warn_html_errors: bool, no_notify: bool, verbose: bool):
    progress = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"))
    with Live(progress, refresh_per_second=50) as live:
        tasks = {host: progress.add_task(f"{host}: waiting", total=len(scan_types)) for host in all_hosts}
        for host in all_hosts:
            logger.debug(f"Processing host: {host} (type: {type(host)})")
            validated_host = validate_target(host)
            logger.debug(f"Validated host: {validated_host} (type: {type(validated_host)})")
            status = {t: {"state": "waiting", "progress": ""} for t in scan_types}
            errors = []
            warnings = 0
            scanner_tasks = []
            # Load the current state for the host
            host_state = state_mgr.load_state(validated_host)
            for t in scan_types:
                status[t]["state"] = "scanning"
                logger.debug(f"Initial status update for {t} on {host}: scanning")
                update_status(progress, tasks, host, status, warnings, len(errors))
                try:
                    scanner = SCANNERS[t](validated_host, config, state_mgr, warn_html_errors)
                    logger.debug(f"Scanner for {t}: {scanner.__class__.__name__}")
                    scanner_task = asyncio.create_task(scanner.run_async())
                    scanner_tasks.append((t, scanner, scanner_task))
                except Exception as e:
                    errors.append(f"{t}: {e}")
                    logger.error(f"{t} scanner failed on {host}: {e}")
                    status[t]["state"] = "error"
                    logger.debug(f"Error status update for {t} on {host}: error")
                    update_status(progress, tasks, host, status, warnings, len(errors))
                progress.update(tasks[host], advance=1)
                live.refresh()
                time.sleep(0.1)

            # Poll for progress and await completion for this host's scanners
            if scanner_tasks:
                last_progress = {t: "" for t, _, _ in scanner_tasks}
                completed = set()
                while len(completed) < len(scanner_tasks):
                    for t, scanner, task in scanner_tasks:
                        if t in completed:
                            continue
                        if task.done():
                            completed.add(t)
                            try:
                                res = task.result()
                                logger.debug(f"Async scan {t} result: {res}")
                                if res:
                                    warnings += sum(len(v) for v in res.values() if isinstance(v, list) and v)
                                # Update host state with scanner's state
                                host_state[t] = scanner.state.get(t, {})
                            except Exception as e:
                                errors.append(f"{t}: {e}")
                                logger.error(f"Async scan {t} failed on {host}: {e}")
                            status[t]["progress"] = scanner.get_progress() if hasattr(scanner, "get_progress") else ""
                            status[t]["state"] = "complete"
                            logger.debug(f"Final status update for {t} on {host}: complete, warnings={warnings}")
                            update_status(progress, tasks, host, status, warnings, len(errors))
                            live.refresh()
                            progress.update(tasks[host], advance=1)
                        else:
                            if hasattr(scanner, "get_progress"):
                                progress_str = scanner.get_progress()
                                if progress_str != last_progress[t]:
                                    status[t]["progress"] = progress_str
                                    last_progress[t] = progress_str
                                    logger.debug(f"Progress update for {t} on {host}: {progress_str}")
                                    update_status(progress, tasks, host, status, warnings, len(errors))
                                    live.refresh()
                    await asyncio.sleep(0.1)
            # Save the combined state for the host
            state_mgr.save_state(validated_host, host_state)
            logger.debug(f"Saved state for {validated_host}: {host_state}")

    if not no_notify:
        logger.debug("Sending scan completion notification")
        await send_notification(title="MCH Scan Complete", message=f"Scanned {len(all_hosts)} hosts.")

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
        # Populate table based on report type
        if type == "critical":
            acao_leak_issues = [i for i in state.get("acao-leak", {}).get("issues", []) if i["status"] == "uncategorized"]
            acao_weak_issues = [k for k, v in state.get("acao-weak", {}).get("issues", {}).items() if v == "uncategorized"]
            table.add_row("ACAO Leaks", f"[red]{len(acao_leak_issues)} leaks[/red]" if acao_leak_issues else "None")
            table.add_row("ACAO Weak Regex", f"[red]{len(acao_weak_issues)} issues[/red]" if acao_weak_issues else "None")
        elif type == "warnings":
            new_ports = [p for p in state["ports"].get("current_open", []) if p not in state["ports"].get("acknowledged", [])]
            fuzz_issues = state["fuzz"].get("issues", []) + state["fuzz"].get("will_fix", [])
            acao_leak_issues = [i for i in state.get("acao-leak", {}).get("issues", []) if i["status"] == "uncategorized"]
            acao_weak_issues = [k for k, v in state.get("acao-weak", {}).get("issues", {}).items() if v == "uncategorized"]
            table.add_row("Unacked Ports", f"[yellow]{len(new_ports)} ports[/yellow]" if new_ports else "None")
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
            table.add_row("ACAO Leak Issues", str([{
                "scheme": i["scheme"],
                "hostname": i["hostname"],
                "endpoint": i["endpoint"],
                "leak_type": i["leak_type"],
                "detail": i["detail"],
                "status": i["status"]
            } for i in state.get("acao-leak", {}).get("issues", [])]))
            table.add_row("ACAO Weak Regex Issues", str(list(state["acao-weak"].get("issues", {}).keys())))
            table.add_row("ACAO Weak Regex Statuses", str({k: v for k, v in state.get("acao-weak", {}).get("issues", {}).items()}))
        # Print table once before detailed lists
        console.print(table)
        # Detailed issue lists for warnings
        if type == "warnings":
            if new_ports:
                console.print("\n[yellow]Unacknowledged Open Ports:[/yellow]")
                for port in sorted(new_ports):
                    console.print(f"  - {port}")
            if fuzz_issues:
                console.print("\n[yellow]Fuzz Issues (Accessible Files/Directories):[/yellow]")
                for path in sorted(fuzz_issues):
                    console.print(f"  - {path}")
            if acao_leak_issues:
                console.print("\n[yellow]ACAO Leak Issues:[/yellow]")
                for issue in sorted(acao_leak_issues, key=lambda x: (x["scheme"], x["hostname"], x["endpoint"], x["leak_type"], x["detail"])):
                    endpoint = f"{issue['scheme']}://{issue['hostname']}{issue['endpoint']}"
                    console.print(f"  - {endpoint} ({issue['leak_type']}: {issue['detail']})")
            if acao_weak_issues:
                console.print("\n[yellow]ACAO Weak Regex Issues:[/yellow]")
                for issue in sorted(acao_weak_issues):
                    # Parse issue key: scheme/hostname/endpoint/weak/origin
                    parts = issue.split("/")
                    if len(parts) >= 4:
                        endpoint = f"{parts[0]}://{parts[1]}{parts[2]}"
                        origin = parts[4] if len(parts) > 4 else "N/A"
                        console.print(f"  - {endpoint} (origin: {origin})")
                    else:
                        console.print(f"  - {issue} (malformed issue key)")

@app.command()
def ack(host: str = typer.Argument(..., help="Host to acknowledge issues")):
    """Interactively acknowledge issues."""
    # Check if terminal supports rich markup
    if not sys.stdout.isatty():
        # Fallback to plain text if not interactive
        print(f"Acknowledging issues for {host} (plain text mode)")
        # Simplified ack logic here if needed, but for now assume interactive
        return

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

    fuzz_issues = state["fuzz"].get("issues", [])
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

    acao_leak_issues = [i for i in state.get("acao-leak", {}).get("issues", []) if i["status"] == "uncategorized"]
    for issue in acao_leak_issues:
        endpoint = f"{issue['scheme']}://{issue['hostname']}{issue['endpoint']}"
        prompt = SingleKeyPrompt(
            message=f"Acknowledge ACAO leak issue {endpoint} ({issue['leak_type']}: {issue['detail']}) on {host}",
            options=["will_fix", "false_positive", "wont_fix", "skip"],
            default="skip"
        )
        response = prompt.ask()
        if response in ["will_fix", "false_positive", "wont_fix"]:
            issue["status"] = response
            console.print(f"[green]Marked {endpoint} as {response.replace('_', '-')}[/green]")

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
