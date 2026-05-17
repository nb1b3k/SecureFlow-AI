"""SecureFlow CLI entry point.

Subcommands:
  scan              Run the full pipeline locally.
  analyze           Alias for `scan` (kept for plan §10 compatibility).
  scan-pr           GitHub-Actions mode: run, write reports, post PR comment.
  generate-report   Render Markdown from an existing JSON report.
  validate-config   Sanity-check a .secureflow.yml.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import typer
from dotenv import load_dotenv

from secureflow import __version__
from secureflow import config as cfg_module
from secureflow.orchestrator import run_pipeline
from secureflow.reporting import (
    build_telemetry,
    maybe_write_step_summary,
    render_markdown_report,
    write_json_report,
    write_sarif_report,
    write_telemetry,
)
from secureflow.utils.logging import configure, get_logger

app = typer.Typer(
    name="secureflow",
    add_completion=False,
    no_args_is_help=True,
    help="SecureFlow AI — agentic DevSecOps PR security review.",
)

# `secureflow eval ...` lives in its own sub-app so the eval-only deps
# (fixture loader, matcher, metrics) only import when used.
from secureflow.eval.cli import app as _eval_app  # noqa: E402

app.add_typer(_eval_app, name="eval")


def _load_env() -> None:
    """Load .env from cwd if present. Silent if missing."""
    load_dotenv(dotenv_path=Path(".env"), override=False)


def _exit_code_for(status: str) -> int:
    return {"PASS": 0, "WARN": 0, "FAIL": 1}.get(status, 2)


def _disable_llm(cfg):
    """Return a Config copy with AI Discovery disabled so the orchestrator
    skips both AI Discovery and (indirectly) Exploitability LLM calls.

    Useful for local dev iterations: scanners still run; reports still
    write; no Gemini quota is consumed.
    """
    return cfg.model_copy(update={
        "ai_discovery": cfg.ai_discovery.model_copy(update={"enabled": False}),
        # Setting max_findings_to_exploit_check to 0 short-circuits the
        # exploitability agent's LLM loop before any call is made.
        "limits": cfg.limits.model_copy(update={"max_findings_to_exploit_check": 0}),
    })


@app.callback()
def _root(
    log_level: str = typer.Option("INFO", "--log-level", help="DEBUG|INFO|WARNING|ERROR"),
    json_logs: bool = typer.Option(False, "--json-logs", help="Force JSON log output."),
    verbose: bool = typer.Option(
        False, "-v", "--verbose",
        help="Shortcut for --log-level DEBUG; prints per-node and per-finding traces.",
    ),
) -> None:
    _force_utf8_stdio()
    _expose_venv_bin_on_path()
    _load_env()
    effective_level = "DEBUG" if verbose else log_level
    configure(level=effective_level, json_output=json_logs or None)


@app.command()
def version() -> None:
    """Print the installed version."""
    typer.echo(__version__)


@app.command("validate-config")
def validate_config(
    config: Path = typer.Option(Path(".secureflow.yml"), "--config", "-c"),
) -> None:
    """Validate a .secureflow.yml. Exit 0 on success."""
    try:
        cfg = cfg_module.load(config)
    except Exception as e:
        typer.secho(f"Invalid config: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Config OK. Provider={cfg.llm.provider} Model={cfg.llm.model}")


@app.command()
def scan(
    repo: Path = typer.Option(Path("."), "--repo", "-r", help="Repository root."),
    output: Path = typer.Option(Path("report.json"), "--output", "-o", help="JSON report path."),
    markdown: Path | None = typer.Option(None, "--markdown", help="Markdown report path."),
    sarif: Path | None = typer.Option(None, "--sarif", help="SARIF report path."),
    telemetry: Path | None = typer.Option(
        None, "--telemetry",
        help="Run-telemetry JSON path (per-node latency, LLM tokens, scanner errors).",
    ),
    config: Path = typer.Option(Path(".secureflow.yml"), "--config", "-c"),
    no_llm: bool = typer.Option(
        False, "--no-llm",
        help="Disable AI Discovery + Exploitability LLM calls. Use during local dev "
             "to avoid Gemini rate limits and speed up iteration.",
    ),
) -> None:
    """Run the full pipeline against a local repo."""
    log = get_logger("cli.scan")
    cfg = cfg_module.load(config)
    if no_llm:
        cfg = _disable_llm(cfg)
        log.info("scan running with --no-llm; LLM agents will be skipped")
    state = run_pipeline(cfg=cfg, repo_path=str(repo))

    json_path = write_json_report(state, output)
    log.info("wrote JSON report: %s", json_path)

    md = render_markdown_report(state)
    if markdown:
        markdown.parent.mkdir(parents=True, exist_ok=True)
        markdown.write_text(md, encoding="utf-8")
        log.info("wrote Markdown report: %s", markdown)

    if sarif and cfg.reporting.output_sarif:
        sarif_path = write_sarif_report(state, sarif)
        log.info("wrote SARIF report: %s", sarif_path)

    if telemetry:
        tel_path = write_telemetry(state, telemetry)
        log.info("wrote telemetry: %s", tel_path)

    decision = state.get("decision") or {}
    status = decision.get("status", "PASS")
    typer.echo(md)
    raise typer.Exit(code=_exit_code_for(status))


@app.command()
def analyze(
    repo: Path = typer.Option(Path("."), "--repo", "-r"),
    output: Path = typer.Option(Path("report.json"), "--output", "-o"),
    config: Path = typer.Option(Path(".secureflow.yml"), "--config", "-c"),
) -> None:
    """Alias for `scan` (kept for backward compatibility with the plan)."""
    return scan(repo=repo, output=output, markdown=None, sarif=None, config=config)


@app.command("scan-pr")
def scan_pr(
    repo: Path = typer.Option(Path("."), "--repo", "-r"),
    output: Path = typer.Option(Path("report.json"), "--output", "-o"),
    markdown: Path = typer.Option(Path("report.md"), "--markdown"),
    sarif: Path = typer.Option(Path("report.sarif"), "--sarif"),
    telemetry: Path = typer.Option(Path("run_telemetry.json"), "--telemetry"),
    config: Path = typer.Option(Path(".secureflow.yml"), "--config", "-c"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Disable LLM agents."),
) -> None:
    """Run in GitHub Actions mode: produce reports and update PR comment."""
    log = get_logger("cli.scan-pr")
    cfg = cfg_module.load(config)
    if no_llm:
        cfg = _disable_llm(cfg)
    state = run_pipeline(cfg=cfg, repo_path=str(repo))

    write_json_report(state, output)
    md = render_markdown_report(state)
    markdown.write_text(md, encoding="utf-8")
    if cfg.reporting.output_sarif:
        write_sarif_report(state, sarif)

    tel = build_telemetry(state)
    write_telemetry(state, telemetry)
    summary_path = maybe_write_step_summary(tel)
    if summary_path:
        log.info("appended run summary to %s", summary_path)

    if cfg.reporting.post_pr_comment:
        _post_pr_comment_if_possible(md)

    decision = state.get("decision") or {}
    status = decision.get("status", "PASS")
    log.info("scan-pr complete: %s", status)
    raise typer.Exit(code=_exit_code_for(status))


@app.command("generate-report")
def generate_report(
    input_json: Path = typer.Option(..., "--input", "-i"),
    fmt: str = typer.Option("markdown", "--format", help="markdown|json"),
) -> None:
    """Render a report from an existing JSON file."""
    if not input_json.exists():
        typer.secho(f"Input not found: {input_json}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    data = json.loads(input_json.read_text(encoding="utf-8"))
    fake_state = {
        "decision": data.get("decision") or {},
        "final_findings": data.get("findings") or [],
        "scanner_errors": data.get("scanner_errors") or {},
        "budget_used": data.get("budget_used") or {},
    }
    if fmt == "markdown":
        typer.echo(render_markdown_report(fake_state))
    elif fmt == "json":
        typer.echo(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        typer.secho(f"Unknown format: {fmt}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ─────────────────────────────────────────────────────────── PR comment helper


def _post_pr_comment_if_possible(body: str) -> None:
    """Best-effort PR-comment posting. Silent if not in GitHub Actions."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    repo = os.environ.get("GITHUB_REPOSITORY")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not repo or not event_path:
        return
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    pr_number = (event.get("pull_request") or {}).get("number")
    if not pr_number:
        return
    from secureflow.tools.github_api import post_or_update_comment

    post_or_update_comment(repo=repo, pr_number=int(pr_number), body=body)


def _force_utf8_stdio() -> None:
    """On Windows, cp1252 stdout can't render emoji in our Markdown reports.

    Reconfigure stdout/stderr to UTF-8 (with replacement on legacy consoles).
    Safe no-op on POSIX terminals that are already UTF-8.
    """
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


def _expose_venv_bin_on_path() -> None:
    """When invoked as a venv entry-point .exe, the venv's bin/Scripts directory
    is not on PATH unless the venv was activated. Scanners that we installed
    into the venv (gitleaks.exe, grype.exe, semgrep.exe) won't be found by
    subprocess until we prepend that directory ourselves.
    """
    exe_dir = Path(sys.executable).parent
    current_path = os.environ.get("PATH", "")
    if str(exe_dir) in current_path.split(os.pathsep):
        return
    os.environ["PATH"] = str(exe_dir) + os.pathsep + current_path


def main() -> None:
    """Console-script entry point."""
    _force_utf8_stdio()
    _expose_venv_bin_on_path()
    try:
        app()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        typer.secho("interrupted", fg=typer.colors.YELLOW, err=True)
        sys.exit(130)


if __name__ == "__main__":
    main()
