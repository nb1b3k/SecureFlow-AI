# Docs-only change

This fixture intentionally has no code, no IaC, no dependencies. It exists to
verify that SecureFlow's policy engine returns PASS when there is nothing
risky to scan and that the LLM agents skip without emitting findings.

A change that only touches Markdown / documentation should never produce
findings or block a PR.
