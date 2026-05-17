"""`secureflow eval ...` Typer sub-app."""

from __future__ import annotations

import json
import os
import platform
from datetime import UTC, datetime
from pathlib import Path

import typer

from secureflow import __version__
from secureflow import config as cfg_module
from secureflow.eval.loader import DEFAULT_FIXTURE_ROOT, load_scenarios
from secureflow.eval.report import render_markdown
from secureflow.eval.runner import run_corpus
from secureflow.utils.logging import get_logger
from secureflow.utils.subprocess_utils import run as run_proc
from secureflow.utils.subprocess_utils import which

app = typer.Typer(
    name="eval",
    help="Evaluate SecureFlow against labeled fixtures.",
    no_args_is_help=True,
)

log = get_logger("cli.eval")


@app.command("list")
def list_scenarios(
    root: Path = typer.Option(DEFAULT_FIXTURE_ROOT, "--root"),
) -> None:
    """List every fixture under `--root` (default: tests/fixtures/)."""
    scenarios = load_scenarios(root)
    if not scenarios:
        typer.echo(f"No scenarios found under {root}")
        raise typer.Exit(code=0)
    for s in scenarios:
        typer.echo(
            f"  {s.scenario_id:40s}  expected={s.expected.expected_decision}  "
            f"labels={len(s.expected.labels)}  ({s.repo_path})"
        )


@app.command("run")
def run_eval(
    root: Path = typer.Option(DEFAULT_FIXTURE_ROOT, "--root"),
    output: Path = typer.Option(Path("eval_report.md"), "--output", "-o"),
    versions_out: Path = typer.Option(
        Path("eval_versions.yaml"), "--versions-out",
        help="Sidecar recording scanner / prompt / model versions for reproducibility.",
    ),
    scenarios_filter: str | None = typer.Option(
        None, "--scenarios",
        help="Comma-separated scenario_ids. Default: all scenarios.",
    ),
    config: Path = typer.Option(Path(".secureflow.yml"), "--config", "-c"),
    no_llm: bool = typer.Option(
        False, "--no-llm",
        help="Run only the scanners_only baseline (no Gemini calls).",
    ),
    llm_concurrency: int | None = typer.Option(
        None, "--llm-concurrency",
        help=(
            "Override limits.max_llm_concurrency for this eval run. Use 1 on "
            "Gemini free tier to stay comfortably under the per-minute cap."
        ),
    ),
    max_findings_to_exploit: int | None = typer.Option(
        None, "--max-findings-to-exploit",
        help="Override limits.max_findings_to_exploit_check. Lower this to spend fewer LLM tokens.",
    ),
    max_patches_per_pr: int | None = typer.Option(
        None, "--max-patches",
        help="Override limits.max_patches_per_pr to bound patch-generation LLM calls.",
    ),
) -> None:
    """Run both pipelines against every fixture and write a Markdown report."""
    cfg = cfg_module.load(config)
    if any(v is not None for v in (llm_concurrency, max_findings_to_exploit, max_patches_per_pr)):
        cfg = cfg.model_copy(update={
            "limits": cfg.limits.model_copy(update={
                k: v for k, v in {
                    "max_llm_concurrency": llm_concurrency,
                    "max_findings_to_exploit_check": max_findings_to_exploit,
                    "max_patches_per_pr": max_patches_per_pr,
                }.items() if v is not None
            }),
        })
        typer.echo(
            f"Eval limits override: concurrency={cfg.limits.max_llm_concurrency} "
            f"max_exploit={cfg.limits.max_findings_to_exploit_check} "
            f"max_patches={cfg.limits.max_patches_per_pr}"
        )
    requested = (
        [s.strip() for s in scenarios_filter.split(",") if s.strip()]
        if scenarios_filter
        else None
    )
    scenarios = load_scenarios(root, scenario_ids=requested)
    if not scenarios:
        typer.secho(f"No scenarios matched under {root}", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Running {len(scenarios)} scenario(s)…")
    modes: tuple = ("scanners_only",) if no_llm else ("scanners_only", "secureflow_full")
    results = run_corpus(scenarios, base_config=cfg, modes=modes)

    report = render_markdown(results)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    typer.echo(f"\nWrote report: {output}")

    versions = _capture_versions(cfg)
    _write_versions(versions_out, versions)
    typer.echo(f"Wrote versions sidecar: {versions_out}")

    # Also emit a JSON sidecar with the raw per-scenario data so an eval CI
    # job can compare across runs.
    json_out = output.with_suffix(".json")
    json_out.write_text(
        json.dumps(
            {
                "results": [r.model_dump() for r in results],
                "versions": versions,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    typer.echo(f"Wrote raw data: {json_out}")


# ─────────────────────────────────────────────────────────── helpers ──


def _capture_versions(cfg) -> dict:
    """Record the versions of everything that affects eval output."""
    return {
        "secureflow_version": __version__,
        "ran_at": datetime.now(UTC).isoformat(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "scanners": {
            "semgrep": _tool_version("semgrep", ["--version"]),
            "gitleaks": _tool_version("gitleaks", ["version"]),
            "grype": _tool_version("grype", ["version"], head_only=True),
        },
        "llm": {
            "provider": cfg.llm.provider,
            "model": os.environ.get("GEMINI_MODEL") or cfg.llm.model,
            "temperature": cfg.llm.temperature,
        },
        "enrichment": {
            "osv": cfg.enrichment.osv,
            "nvd": cfg.enrichment.nvd,
            "mitre": cfg.enrichment.mitre,
        },
    }


def _tool_version(binary: str, args: list[str], *, head_only: bool = False) -> str | None:
    """Best-effort `<tool> --version` capture."""
    if which(binary) is None:
        return None
    try:
        proc = run_proc([binary, *args], timeout=10)
    except Exception:
        return None
    out = proc.stdout.strip()
    if not out:
        out = proc.stderr.strip()
    if head_only:
        # grype's `version` prints a header + key:val lines; just take a few lines.
        return "\n".join(out.splitlines()[:5])
    return out.splitlines()[0] if out else None


def _write_versions(path: Path, versions: dict) -> None:
    import yaml

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(versions, sort_keys=False), encoding="utf-8")
