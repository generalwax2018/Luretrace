"""Integration tests are collected but skipped unless explicitly enabled.

Enable with:  pytest --run-integration     or     RUN_INTEGRATION=1 pytest
They still skip individually if their required credentials / sample URL aren't set.
"""
import os

import pytest


def pytest_addoption(parser):
    parser.addoption("--run-integration", action="store_true", default=False,
                     help="run integration tests that need live services or a browser")


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "integration: needs live services or a real browser; skipped by default")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-integration") or os.environ.get("RUN_INTEGRATION"):
        return
    skip = pytest.mark.skip(reason="integration test — use --run-integration or RUN_INTEGRATION=1")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)
