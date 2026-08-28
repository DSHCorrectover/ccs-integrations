"""Shared pytest fixtures for ccs-pydantic-ai tests."""
from __future__ import annotations

import pytest

from ccs_pydantic_ai import CCSConfig, ReceiptRecord


@pytest.fixture
def in_process_config() -> CCSConfig:
    """Deterministic in-process config that collects receipts into a list."""
    records: list[ReceiptRecord] = []
    config = CCSConfig(
        deployment_mode="in-process",
        seed=b"unit-test-seed-please-ignore",
        issuer="ccs-pydantic-ai/test",
        audience="pytest",
        trace_id="pytest-trace-001",
        sink=records.append,
    )
    config._records = records  # type: ignore[attr-defined]
    return config


@pytest.fixture
def silent_config() -> CCSConfig:
    """Config with a no-op sink for tests that assert via builder directly."""
    return CCSConfig(
        deployment_mode="in-process",
        seed=b"unit-test-seed-please-ignore",
        issuer="ccs-pydantic-ai/test",
        audience="pytest",
        trace_id="pytest-trace-001",
        sink=lambda r: None,
    )
