"""Discover and load eval fixtures from `tests/fixtures/`.

A fixture is any directory that contains an `expected.yaml`. The directory
itself is the scan target; everything else under it is the snapshot of
the repo as the scenario expects it to look.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import yaml

from secureflow.eval.schema import ScenarioExpected
from secureflow.utils.logging import get_logger

log = get_logger("eval.loader")


@dataclass
class Scenario:
    """One fixture: a path to scan + its expected ground truth."""

    scenario_id: str
    repo_path: Path
    expected: ScenarioExpected


DEFAULT_FIXTURE_ROOT = Path("tests/fixtures")


def iter_scenarios(root: Path | str = DEFAULT_FIXTURE_ROOT) -> Iterator[Scenario]:
    """Yield every scenario whose directory contains `expected.yaml`."""
    root = Path(root)
    if not root.exists():
        return
    for expected_path in sorted(root.rglob("expected.yaml")):
        try:
            data = yaml.safe_load(expected_path.read_text(encoding="utf-8")) or {}
            expected = ScenarioExpected.model_validate(data)
        except Exception as e:
            log.warning(
                "skipping malformed fixture",
                extra={"path": str(expected_path), "err": str(e)},
            )
            continue
        yield Scenario(
            scenario_id=expected.scenario_id,
            repo_path=expected_path.parent,
            expected=expected,
        )


def load_scenarios(
    root: Path | str = DEFAULT_FIXTURE_ROOT,
    *,
    scenario_ids: list[str] | None = None,
) -> list[Scenario]:
    """Return scenarios, optionally filtered to a given set of IDs."""
    scenarios = list(iter_scenarios(root))
    if scenario_ids:
        wanted = set(scenario_ids)
        scenarios = [s for s in scenarios if s.scenario_id in wanted]
    return scenarios
