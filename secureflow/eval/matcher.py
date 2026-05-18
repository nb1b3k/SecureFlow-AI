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
    # W22 — secondary findings are legitimate additional findings on the
    # same target as an already-matched primary (e.g. additional CVEs in
    # the same vulnerable package, or additional Checkov sub-checks on
    # the same IaC resource). They don't count as TP (1 label still
    # equals 1 TP) but also don't count as FP — the system correctly
    # detected the labeled issue and these are honest related findings.
    secondary: int = 0


def match_findings_to_labels(
    findings: Iterable[dict],
    labels: list[ExpectedLabel],
    *,
    scenario_repo: str | Path | None = None,
) -> MatchResult:
    """Greedy 1:1 assignment of findings to labels. Returns TP / FP / FN.

    Once a label matches a primary finding, additional findings that hit
    the same target (e.g. more CVEs in the same vulnerable package, or
    additional Checkov sub-checks on the same IaC resource) get credited
    as `secondary` rather than counted as FP. The matcher's job is to
    measure how well the system identifies labeled issues; multiple
    findings on the same target represent the same underlying issue from
    the system's perspective, not separate false positives.
    """
    findings_list = list(findings)
    used_finding_idxs: set[int] = set()
    secondary_finding_idxs: set[int] = set()
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
            # W22 — sweep any unused findings on the same target as the
            # primary and mark them as secondary. They neither TP nor FP.
            primary = findings_list[matched_idx]
            for idx, f in enumerate(findings_list):
                if idx in used_finding_idxs or idx in secondary_finding_idxs:
                    continue
                if _is_secondary_match(primary, f, label, scenario_repo):
                    secondary_finding_idxs.add(idx)
        else:
            unmatched_label_ids.append(label.id)

    tp = len(matched_label_ids)
    fn = len(unmatched_label_ids)
    secondary = len(secondary_finding_idxs)
    fp = len(findings_list) - tp - secondary
    return MatchResult(
        tp=tp,
        fp=fp,
        fn=fn,
        matched_label_ids=matched_label_ids,
        unmatched_label_ids=unmatched_label_ids,
        secondary=secondary,
    )


def _is_secondary_match(
    primary: dict,
    candidate: dict,
    label: ExpectedLabel,
    scenario_repo: str | Path | None,
) -> bool:
    """True when `candidate` is a legitimate additional finding on the
    same target as `primary`.

    Three target categories:

    1. **Dependency findings** (label.type == "vulnerable_dependency"):
       grype reports one finding per CVE per package, so Django 2.2.0
       alone surfaces ~15 separate findings even though the developer's
       remediation is a single `Django` upgrade. Any other grype/osv
       finding on the same `package@version` symbol is secondary.

    2. **Checkov IaC findings** (source == "checkov"): a single Terraform
       resource often produces 5+ separate Checkov findings (encryption,
       logging, versioning, public-access, etc.). If the label expects
       one of them and the system flags adjacent issues, those are
       legitimate review surface, not FP. We treat any other Checkov
       finding on the same file as secondary.

    3. **Everything else** (SAST / secrets / AI Discovery): we do NOT
       auto-credit secondaries. Different SAST rules on the same line
       can be genuinely different bugs (SQLi + old crypto API on the
       same `cursor.execute` call, say). Stricter labels keep the
       eval honest for those categories.
    """
    if label.type == "vulnerable_dependency":
        ps = (primary.get("symbol") or "").lower()
        cs = (candidate.get("symbol") or "").lower()
        cs_source = candidate.get("source")
        if cs_source not in {"grype", "osv"}:
            return False
        return bool(ps) and ps == cs
    if primary.get("source") == "checkov" and candidate.get("source") == "checkov":
        return _finding_path(primary, scenario_repo) == _finding_path(candidate, scenario_repo)
    return False
