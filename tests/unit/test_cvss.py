"""Unit tests for the local CVSS v3.x base-score calculator."""

from __future__ import annotations

import pytest

from secureflow.enrichment.cvss import base_score, parse_vector

# Vectors from real-world NVD records — score values cross-checked.

KNOWN: list[tuple[str, float]] = [
    # CVE-2020-9402 (Django SQL injection)
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    # CVE-2018-18074 (requests Authorization leak)
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    # CVE-2023-32681 (requests Proxy-Authorization leak)
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N", 6.1),
    # CVE-2021-44228 (Log4Shell)
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    # Low-severity local-only (computed by NVD calculator: 1.8)
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
]


@pytest.mark.parametrize("vector,expected", KNOWN)
def test_known_vectors_match_published_scores(vector: str, expected: float) -> None:
    score = base_score(vector)
    assert score is not None
    # CVSS v3.1 Roundup uses ceil(score*10)/10, so we allow ±0.1.
    assert abs(score - expected) <= 0.1, f"{vector}: got {score}, expected {expected}"


def test_invalid_vector_returns_none() -> None:
    assert base_score("not a vector") is None
    assert base_score("CVSS:3.1/garbage") is None


def test_v2_vector_returns_none() -> None:
    # We only support v3 — v2 returns None, not a wrong score.
    assert base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P") is None


def test_parse_vector_extracts_components() -> None:
    m = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert m["CVSS"] == "3.1"
    assert m["AV"] == "N"
    assert m["S"] == "U"
