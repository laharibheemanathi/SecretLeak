"""Entropy helper tests."""

from __future__ import annotations

from app.detectors.entropy import (
    is_high_entropy_candidate,
    looks_like_common_artifact,
    shannon_entropy,
)


def test_shannon_entropy_known_values():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert abs(shannon_entropy("abcd") - 2.0) < 1e-9


def test_artifacts_excluded():
    assert looks_like_common_artifact("a" * 40)  # uniform hex-ish blob
    assert looks_like_common_artifact("d1a0f0e1b2c3d4e5f60718293a4b5c6d7e8f9a0b")  # git sha shape
    assert looks_like_common_artifact("a" * 32)
    assert looks_like_common_artifact("123e4567-e89b-12d3-a456-426614174000")
    assert looks_like_common_artifact("123456789012345678901234")
    assert not looks_like_common_artifact("kR8mQp2Nt5Vw7Xa9Zc3Bd6Ef1Gh4Jk8Lm0Pn")


def test_entropy_gate():
    assert is_high_entropy_candidate("kR8mQp2Nt5Vw7Xa9Zc3Bd6Ef1Gh4Jk8Lm0Pn")
    assert not is_high_entropy_candidate("short1")            # too short
    assert not is_high_entropy_candidate("a" * 40)            # no variation
    assert not is_high_entropy_candidate("ONLYLETTERSONLYLETTERSONLYLETTERSXX")  # no digits
    assert not is_high_entropy_candidate("123456789012345678901234567890")      # digits only
