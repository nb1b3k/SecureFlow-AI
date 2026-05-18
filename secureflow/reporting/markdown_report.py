"""Markdown report — the PR comment body and the local CLI's human view."""

from __future__ import annotations

from secureflow.utils.secret_masker import mask

_STATUS_BADGE = {
    "PASS": "✅ PASS",
    "WARN": "⚠️ WARN",
    "FAIL": "❌ FAIL",
}

# Scanner-errors keys that come from LLM-using agents. Errors under other keys
# (gitleaks, semgrep, grype) are scanner failures and live in the "Notes"
# section, not the top banner.
_LLM_AGENTS = ("ai_discovery", "exploitability", "patch", "threat_model")

_STRIDE_LABELS = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "information_disclosure": "Information Disclosure",
    "denial_of_service": "Denial of Service",
    "elevation_of_privilege": "Elevation of Privilege",
}

_CHANGE_TYPE_LABELS = {
    "new_endpoint": "New endpoint",
    "new_admin_route": "New admin route",
    "new_auth_logic": "New auth logic",
    "auth_logic_change": "Auth logic change",
    "new_external_integration": "New external integration",
    "new_data_export": "New data export",
    "new_file_upload": "New file upload",
    "new_payment_logic": "New payment logic",
    "new_trust_boundary": "New trust boundary",
    "new_cross_tenant_path": "New cross-tenant path",
    "new_iac_resource": "New IaC resource",
    "increased_blast_radius": "Increased blast radius",
    "other": "Design change",
}

# Substrings in a skip reason that indicate AI analysis was truncated rather
# than intentionally disabled. We want reviewers to know "this PR comment
# does NOT reflect a full LLM pass" without inferring it from the Notes list.
_ACTIONABLE_SKIPS = (
    "budget",
    "rate_limited",
    "ratelimitederror",        # GroqRateLimitedError surfaces by class name
    "resource_exhausted",
    "quota",
    "llm_unavailable",
    "groqconfigerror",
)


def _llm_skip_banner(scanner_errors: dict) -> str:
    """Return a top-of-report callout when LLM agents skipped for actionable
    reasons (budget exhausted, rate-limited, API key missing). Empty string
    when LLM agents ran cleanly, were intentionally disabled, or only skipped
    because there was nothing for them to analyse.
    """
    flagged: list[tuple[str, str]] = []
    for agent in _LLM_AGENTS:
        reason = scanner_errors.get(agent)
        if not reason:
            continue
        low = str(reason).lower()
        if any(needle in low for needle in _ACTIONABLE_SKIPS):
            flagged.append((agent, str(reason)))
    if not flagged:
        return ""
    lines = [
        "> [!WARNING]",
        "> **AI analysis was partially skipped — results are scanner-only for the items below.**",
        "> The deterministic policy decision still applies, but exploitability reasoning, AI Discovery,",
        "> and/or verified patches did not run on every finding. Re-running after the cause is",
        "> resolved (raise the budget, refresh the API key, wait out the rate-limit window) will",
        "> populate the missing analyses.",
        ">",
    ]
    for agent, reason in flagged:
        # Reasons can be long (Gemini's 429 body, etc.); trim for the banner.
        trimmed = reason if len(reason) <= 220 else reason[:217] + "…"
        lines.append(f"> - `{agent}`: {trimmed}")
    return "\n".join(lines)


def render_markdown_report(state: dict) -> str:
    decision = state.get("decision") or {}
    findings = state.get("final_findings") or state.get("mapped_findings") or []
    scanner_errors = state.get("scanner_errors") or {}
    budget = state.get("budget_used") or {}
    pr_context = state.get("pr_context") or {}

    status = decision.get("status", "PASS")
    score = decision.get("risk_score", 0)
    summary = decision.get("summary", "")

    blocking, ai_findings, info = _partition(findings, decision.get("finding_ids") or [])

    parts: list[str] = [
        "# SecureFlow AI Security Review",
        "",
    ]
    pr_line = _pr_header_line(pr_context)
    if pr_line:
        parts.extend([pr_line, ""])
    skip_banner = _llm_skip_banner(scanner_errors)
    if skip_banner:
        parts.extend([skip_banner, ""])
    parts.extend([
        f"**Decision:** {_STATUS_BADGE.get(status, status)}",
        f"**Risk score:** {score}/100",
        "",
        summary,
        "",
    ])

    if blocking:
        parts.append("## Blocking findings")
        parts.append("")
        for f in blocking:
            parts.extend(_render_finding(f))
        parts.append("")

    if ai_findings:
        parts.append("## AI-discovered findings requiring review")
        parts.append("")
        for f in ai_findings:
            parts.extend(_render_finding(f))
        parts.append("")

    if info:
        parts.append("<details><summary>Other findings</summary>")
        parts.append("")
        for f in info:
            parts.extend(_render_finding(f))
        parts.append("")
        parts.append("</details>")
        parts.append("")

    threat_model = state.get("threat_model_findings") or []
    if threat_model:
        parts.append("## Threat Modeling Delta")
        parts.append("")
        parts.append(
            "_Design-level threats introduced by this PR. Independent of the "
            "code-level findings above — a clean code review can still merge "
            "a design regression._"
        )
        parts.append("")
        for t in threat_model:
            parts.extend(_render_threat_model_item(t))
        parts.append("")

    if not findings and not threat_model:
        parts.append("_No findings reported by any agent._")
        parts.append("")

    if scanner_errors:
        parts.append("## Notes")
        parts.append("")
        for component, error in scanner_errors.items():
            parts.append(f"- `{component}`: {error}")
        parts.append("")

    if budget:
        parts.append(
            f"<sub>Budget — tokens_in: {budget.get('tokens_in', 0)}, "
            f"tokens_out: {budget.get('tokens_out', 0)}, "
            f"llm_calls: {budget.get('llm_calls', 0)}</sub>"
        )

    return "\n".join(parts)


def _pr_header_line(pr_context: dict) -> str:
    """Single-line PR identifier if we have one. Empty string otherwise."""
    repo = pr_context.get("repo_name")
    pr = pr_context.get("pr_number")
    head = pr_context.get("head_branch")
    base = pr_context.get("base_branch")
    bits: list[str] = []
    if repo and pr:
        bits.append(f"**PR:** [{repo}#{pr}](https://github.com/{repo}/pull/{pr})")
    elif pr:
        bits.append(f"**PR:** #{pr}")
    if base and head:
        bits.append(f"`{head}` → `{base}`")
    return "  ·  ".join(bits)


def _partition(
    findings: list[dict], blocking_ids: list[str]
) -> tuple[list[dict], list[dict], list[dict]]:
    blocking: list[dict] = []
    ai: list[dict] = []
    other: list[dict] = []
    blocking_set = set(blocking_ids)
    for f in findings:
        if f.get("id") in blocking_set:
            blocking.append(f)
        elif f.get("source") == "ai_discovery":
            ai.append(f)
        else:
            other.append(f)
    return blocking, ai, other


def _render_finding(f: dict) -> list[str]:
    title = f.get("title") or "(untitled)"
    sev = f.get("severity", "info")
    conf = f.get("confidence", 0.0)
    file_path = f.get("file_path")
    start = f.get("start_line")
    cwe = ", ".join(f.get("cwe") or [])
    owasp = ", ".join(f.get("owasp") or [])
    attack = ", ".join(f.get("mitre_attack") or [])
    cve = ", ".join(f.get("cve") or [])
    rec = f.get("recommendation") or ""
    evidence = f.get("evidence") or ""

    loc = f"{file_path}:{start}" if file_path and start else (file_path or "—")
    cvss = f.get("cvss_score")
    cvss_vec = f.get("cvss_vector") or ""
    refs = [r for r in (f.get("references") or []) if isinstance(r, str)]
    src = f.get("source")
    src_label = str(src) if src else ""
    # Tag dependency findings with their scope (direct_runtime / direct_dev /
    # transitive / unknown) so the reviewer can tell at a glance whether a
    # CVE ships with the app, is a build-only dep, or comes in transitively.
    if src in {"grype", "osv"}:
        scope = f.get("dependency_scope")
        if scope and scope != "unknown":
            src_label = f"{src_label} ({scope})"
    bits = [
        f"### {title}",
        f"- **Severity:** {sev}  ·  **Confidence:** {conf:.2f}  ·  **Source:** {src_label}",
        f"- **Location:** `{loc}`",
    ]
    meta = []
    if cwe:
        meta.append(f"CWE: {cwe}")
    if owasp:
        meta.append(f"OWASP: {owasp}")
    if attack:
        meta.append(f"ATT&CK: {attack}")
    if cve:
        meta.append(f"CVE: {cve}")
    if cvss is not None:
        cvss_str = f"CVSS: {cvss:.1f}"
        if cvss_vec:
            cvss_str += f" ({cvss_vec})"
        meta.append(cvss_str)
    if meta:
        bits.append(f"- {' · '.join(meta)}")
    if evidence:
        masked = mask(evidence).strip()
        if masked:
            bits.append("")
            bits.append("```")
            bits.append(masked[:1000])
            bits.append("```")
    if rec:
        bits.append("")
        bits.append(f"**Recommendation:** {rec}")

    # Render the actual fix when one is available.
    bits.extend(_render_patch(f))

    if refs:
        bits.append("")
        bits.append("**References:**")
        for r in refs[:5]:
            bits.append(f"- {r}")
    bits.append("")
    return bits


def _render_patch(f: dict) -> list[str]:
    """Render the suggested fix as a GitHub `suggestion` block when we have a
    verified single-hunk patch, falling back to a plain unified-diff for
    multi-hunk changes and to `replacement_code` for AI-discovery findings
    that the orchestrator couldn't auto-verify.

    `suggestion` blocks render as a one-click "Apply suggestion" button in
    GitHub PR review threads, but ONLY when posted as a *line comment* on
    the relevant diff range. We emit them in the bot comment too — they
    still render as a normal code block there, and any reviewer who copies
    the bot's output into a line comment gets the apply button.
    """
    status = f.get("patch_status") or "none"
    diff = (f.get("patch_unified_diff") or "").strip()
    replacement = (f.get("replacement_code") or "").strip()
    explanation = (f.get("patch_explanation") or "").strip()

    if not (diff or replacement):
        return []
    out = ["", "**Suggested fix:**"]
    if status == "verified":
        out.append("_(scanner re-run on the patched tree no longer reports this finding)_")
    elif status in {"suggested", "unverified"}:
        out.append("_(generated by LLM; manually verify before applying)_")
    elif status == "not_applicable":
        out.append("_(AI-discovered finding — auto-verification not available; review carefully)_")

    if replacement:
        # GitHub's `suggestion` block triggers the Apply-suggestion button
        # when this comment lands on the right diff range.
        out.extend(["```suggestion", replacement[:2000], "```"])
    elif diff:
        out.extend(["```diff", diff[:2000], "```"])

    if explanation:
        out.append(f"_{explanation[:400]}_")

    # Surface the second-opinion review verdict and any concerns. The
    # review pass runs after the patch is applied and the scanner
    # re-runs; it answers "does the replacement actually fix the vuln
    # AND match the code context?" — questions the scanner can't fully
    # answer alone. A "reject" verdict downgrades `patch_status`
    # upstream; we still show the patch so the reviewer can see the
    # full picture (proposed fix + reasons the LLM thinks it's bad).
    verdict = f.get("patch_review_verdict")
    if verdict:
        review_conf = f.get("patch_review_confidence")
        concerns = list(f.get("patch_review_concerns") or [])
        line_parts = [f"**Patch review:** `{verdict}`"]
        if review_conf is not None:
            line_parts.append(f"(confidence {float(review_conf):.2f})")
        out.append("")
        out.append(" ".join(line_parts))
        if concerns:
            out.append("**Review concerns:**")
            for c in concerns[:5]:
                out.append(f"- {c}")
    return out


def _render_threat_model_item(t: dict) -> list[str]:
    """Render one threat-modeling-delta item. Different shape from `_render_finding`
    because threats are about design surface, not specific lines of code.
    """
    title = t.get("title") or "(untitled threat)"
    change_type = _CHANGE_TYPE_LABELS.get(t.get("change_type", "other"), "Design change")
    sev = t.get("severity", "medium")
    conf = float(t.get("confidence") or 0.0)
    decision = t.get("suggested_decision") or "WARN"
    file_path = t.get("file_path")
    start = t.get("start_line")
    desc = (t.get("description") or "").strip()
    excerpt = (t.get("evidence_excerpt") or "").strip()
    stride = [_STRIDE_LABELS.get(s, s) for s in (t.get("stride") or [])]
    abuse = list(t.get("abuse_cases") or [])
    mitigations = list(t.get("mitigations") or [])

    loc = f"{file_path}:{start}" if file_path and start else (file_path or "—")
    bits = [
        f"### {title}",
        f"- **Change type:** {change_type}",
        f"- **Severity:** {sev}  ·  **Confidence:** {conf:.2f}  ·  **Suggested:** {decision}",
        f"- **Location:** `{loc}`",
    ]
    if stride:
        bits.append(f"- **STRIDE:** {', '.join(stride)}")
    if desc:
        bits.append("")
        bits.append(desc)
    if excerpt:
        masked = mask(excerpt).strip()
        if masked:
            bits.append("")
            bits.append("```")
            bits.append(masked[:600])
            bits.append("```")
    if abuse:
        bits.append("")
        bits.append("**Abuse cases:**")
        for a in abuse[:5]:
            bits.append(f"- {a}")
    if mitigations:
        bits.append("")
        bits.append("**Required mitigations before merge:**")
        for m in mitigations[:5]:
            bits.append(f"- {m}")
    bits.append("")
    return bits
