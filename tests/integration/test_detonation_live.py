"""Live detonation against a real URL. Opens the actual page — run on an isolated host only.

Set LURETRACE_TEST_URL to the sample. Optionally set LURETRACE_TEST_EXPECT to the label you
expect (clean | suspicious | malicious) to assert detection, otherwise the test just checks a
well-formed verdict is produced.
"""
import asyncio
import os

import pytest

pytestmark = pytest.mark.integration


def test_detonate_sample_url(tmp_path):
    url = os.environ.get("LURETRACE_TEST_URL")
    if not url:
        pytest.skip("set LURETRACE_TEST_URL to a sample URL to detonate")
    pytest.importorskip("playwright")

    from luretrace.config import Config
    from luretrace.pipeline import scan_url

    cfg = Config(output_dir=str(tmp_path))
    verdict = asyncio.run(scan_url(url, cfg))

    assert verdict.label in ("clean", "suspicious", "malicious", "skipped")
    assert verdict.hops, "expected at least one captured hop"
    assert verdict.artifacts_dir, "expected artifacts to be written"

    expect = os.environ.get("LURETRACE_TEST_EXPECT")
    if expect:
        assert verdict.label == expect, (
            f"expected {expect!r} for {url!r}, got {verdict.label!r} "
            f"(score {verdict.score}, signals: {[s.name for s in verdict.signals]})")


def test_detonate_benign_control(tmp_path):
    """A plain page with no credential form should never score as malicious."""
    url = os.environ.get("LURETRACE_BENIGN_URL")
    if not url:
        pytest.skip("set LURETRACE_BENIGN_URL to a known-good page for the control check")
    pytest.importorskip("playwright")

    from luretrace.config import Config
    from luretrace.pipeline import scan_url

    verdict = asyncio.run(scan_url(url, Config(output_dir=str(tmp_path))))
    assert verdict.label in ("clean", "skipped"), (
        f"benign control {url!r} scored {verdict.label!r} — possible false positive")
