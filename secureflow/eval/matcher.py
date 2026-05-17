"""Match reported findings against a scenario's expected labels.

A label and a finding match when:
  - normalized file paths match (case-insensitive, slashes normalized,
    trailing relative-path artifacts stripped), AND
  - line ranges overlap with `LINE_TOLERANCE` lines of slack, AND
  - the label `type` aliases to the finding's rule_id (scanners) or
    title (AI discovery).

A finding can satisfy at most one label. A label can be satisfied by at
most one finding. Anything left over goes to FP / FN.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath

import yaml

from secureflow.eval.schema import ExpectedLabel
from secureflow.utils.logging import get_logger

log = get_logger("eval.matcher")

LINE_TOLERANCE = 5
_ALIAS_PATH = Path(__file__).parent / "label_aliases.yaml"


# ─────────────────────────────────────────────────────────── alias table ──


@lru_cache(maxsize=1)
def _aliases() -> dict[str, dict]:
    if not _ALIAS_PATH.exists():
        log.warning("label_aliases.yaml missing")
        return {}
    try:
        data = yaml.safe_load(_ALIAS_PATH.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        log.warning("label_aliases.yaml parse error: %s", e)
        return {}
    return {k: v or {} for k, v in data.items() if isinstance(v, dict)}


def aliases_for(label_type: str) -> dict[str, list[str]]:
    """Return `{scanner_rule_patterns: [...], ai_title_keywords: [...]}` for a label type."""
    entry = _aliases().get(label_type) or {}
    return {
        "scanner_rule_patterns": [p.lower() for p in entry.get("scanner_rule_patterns") or []],
        "ai_title_keywords": [k.lower() for k in entry.get("ai_title_keywords") or []],
    }


# ────────────────────────────────────────────────────── individual match ──


def _norm_path(p: str | None) -> str:
    if not p:
        return ""
    s = p.replace("\\", "/").lstrip("./")
    return str(PurePosixPath(s)).lower()


def _lines_overlap(label_range: list[int] | None, finding: dict, tolerance: int = LINE_TOLERANCE) -> bool:
    """True if the label's line range overlaps the finding's range with tolerance.

    If the label has no `line_range` (e.g. dependency CVEs), match on path
    alone so the type+location can still satisfy the label.
    """
    if not label_range:
        return True
    lstart, lend = label_range[0], label_range[1] if len(label_range) > 1 else label_range[0]
    fstart = finding.get("start_line") or 0
    fend = finding.get("end_line") or fstart
    # Expand the label range by `tolerance` lines on each side.
    return not (fend < (lstart - tolerance) or fstart > (lend + tolerance))


def _type_matches(label_type: str, finding: dict) -> bool:
    """True if the finding's rule/title satisfies the label's type aliases."""
    aliases = aliases_for(label_type)
    rule = (finding.get("rule_id") or "").lower()
    title = (finding.get("title") or "").lower()
    source = finding.get("source") or ""

    # Scanner findings match by rule_id (or, as fallback, title).
    if source != "ai_discovery":
        for pat in aliases["scanner_rule_patterns"]:
            if pat in rule or pat in title:
                return True
        return False

    # AI-discovery findings match by title keywords.
    for kw in aliases["ai_title_keywords"]:
        if kw in title:
            return True
    return False


def _dep_matches(label: ExpectedLabel, finding: dict) -> bool:
    """Match a vulnerable_dependency label to a grype finding via (pkg, version).

    grype findings carry `symbol = "<package>@<version>"`. We tolerate
    case-insensitive comparison and missing version (some label authors
    omit it).
    """
    symbol = (finding.get("symbol") or "").lower()
    pkg = (label.package or "").lower()
    ver = (label.version or "").lower()
    if not pkg:
        return False
    if pkg not in symbol:
        return False
    if ver and ver not in symbol:
        return False
    return True


def _label_path(label_file: str, scenario_repo: str | Path | None = None) -> str:
    """Labels are written relative to the fixture root. Findings may be
    absolute or relative to the scan target. Normalize to a common form."""
    return _norm_path(label_file)


def _finding_path(finding: dict, scenario_repo: str | Path | None = None) -> str:
    raw = finding.get("file_path")
    if not raw:
        return ""
    norm = _norm_path(raw)
    # If the scenario repo is "tests/fixtures/X" and gitleaks reports
    # "tests/fixtures/X/config.py", strip the prefix so it matches the
    # label's relative path.
    if scenario_repo is not None:
        prefix = _norm_path(str(scenario_repo))
        if prefix and norm.startswith(prefix + "/"):
            return norm[len(prefix) + 1 :]
    return norm


# ────────────────────────────────────────────────────── public API ──


@dataclass
class MatchResult:
    tp: int
    fp: int
    fn: int
    matched_label_ids: list[str]
    unmatched_label_ids: list[str]


def match_findings_to_labels(
    findings: Iterable[dict],
    labels: list[ExpectedLabel],
    *,
    scenario_repo: str | Path | None = None,
) -> MatchResult:
    """Greedy 1:1 assignment of findings to labels. Returns TP / FP / FN."""
    findings_list = list(findings)
    used_finding_idxs: set[int] = set()
    matched_label_ids: list[str] = []
    unmatched_label_ids: list[str] = []

    for label in labels:
        label_path = _label_path(label.file, scenario_repo)
        is_dep = label.type == "vulnerable_dependency"
        matched_idx: int | None = None
        for idx, f in enumerate(findings_list):
            if idx in used_finding_idxs:
                continue
            # Dependency findings from grype have file_path=None (a CVE is
            # bound to a package@version, not a source line). For those we
            # match on (package, version) instead of path/line.
            if is_dep:
                if not _dep_matches(label, f):
                    continue
            else:
                if _finding_path(f, scenario_repo) != label_path:
                    continue
                if not _lines_overlap(label.line_range, f):
                    continue
            if not _type_matches(label.type, f):
                continue
            matched_idx = idx
            break
        if matched_idx is not None:
            used_finding_idxs.add(matched_idx)
            matched_label_ids.append(label.id)
        else:
            unmatched_label_ids.append(label.id)

    tp = len(matched_label_ids)
    fn = len(unmatched_label_ids)
    fp = len(findings_list) - tp
    return MatchResult(
        tp=tp,
        fp=fp,
        fn=fn,
        matched_label_ids=matched_label_ids,
        unmatched_label_ids=unmatched_label_ids,
    )
