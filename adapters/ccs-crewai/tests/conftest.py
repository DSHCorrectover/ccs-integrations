"""Shared pytest fixtures and helpers for ccs-crewai tests."""
from __future__ import annotations

import sys
import pathlib

_tests_dir = str(pathlib.Path(__file__).resolve().parent)
if _tests_dir not in sys.path:
    sys.path.insert(0, _tests_dir)

import pytest

from ccs_crewai import CCSConfig, PolicyDecision
from ccs_crewai.guardrail import CCSGuardrailProvider

TEST_SEED = b"ccs-crewai-unit-test-seed"


@pytest.fixture
def records():
    return []


@pytest.fixture
def allow_all_config(records):
    return CCSConfig(
        deployment_mode="in-process",
        seed=TEST_SEED,
        issuer="ccs-crewai/test",
        audience="pytest",
        trace_id="pytest-trace-001",
        sink=records.append,
    )


@pytest.fixture
def denying_config(records):
    def deny_all(tool_name, tool_args, runtime_context=None):
        return PolicyDecision(allowed=False, reason="test_deny")
    return CCSConfig(
        deployment_mode="in-process",
        seed=TEST_SEED,
        issuer="ccs-crewai/test",
        audience="pytest",
        trace_id="pytest-trace-001",
        sink=records.append,
        policy=deny_all,
    )


@pytest.fixture
def provider(allow_all_config):
    return CCSGuardrailProvider(allow_all_config)


@pytest.fixture
def denying_provider(denying_config):
    return CCSGuardrailProvider(denying_config)
