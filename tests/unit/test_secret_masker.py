"""Unit tests for the secret masker."""

from __future__ import annotations

from secureflow.utils.secret_masker import find_hits, mask


def test_masks_aws_access_key() -> None:
    text = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
    masked = mask(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in masked
    assert "AKIA" in masked and "EXAMPLE"[-4:] in masked


def test_masks_stripe_live_key() -> None:
    text = 'k = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"'
    masked = mask(text)
    assert "sk_live_4eC39HqLyjWDarjtT1zdp7dc" not in masked


def test_does_not_mangle_innocent_strings() -> None:
    text = "hello world, this is a normal log line"
    assert mask(text) == text


def test_find_hits_locates_secrets() -> None:
    text = 'token = "AKIAIOSFODNN7EXAMPLE"'
    hits = find_hits(text)
    assert any(h.kind == "AWS_ACCESS_KEY" for h in hits)


def test_empty_input_safe() -> None:
    assert mask("") == ""
    assert mask(None) is None  # type: ignore[arg-type]
