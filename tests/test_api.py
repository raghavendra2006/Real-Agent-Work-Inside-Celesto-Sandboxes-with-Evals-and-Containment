"""Tests for FastAPI endpoints and Pydantic validation rules."""

import pytest
from fastapi.testclient import TestClient

from app import app, RunCreate


@pytest.fixture
def client():
    return TestClient(app)


def test_health_endpoint(client):
    """GET /health returns 200 with status ok."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_pydantic_run_create_valid():
    """Valid RunCreate payload passes validation."""
    data = RunCreate(
        run_id="test-run-1",
        sandbox_name="sbx-1234abcd",
        problem_id="package-detonation",
        state="running",
        execution_target="celesto_sandbox",
    )
    assert data.sandbox_name == "sbx-1234abcd"
    assert data.execution_target == "celesto_sandbox"


def test_pydantic_invalid_execution_target():
    """execution_target must be 'celesto_sandbox'."""
    with pytest.raises(ValueError, match="execution_target must be 'celesto_sandbox'"):
        RunCreate(
            run_id="test-run-bad",
            sandbox_name="sbx-1234abcd",
            execution_target="docker_container",
        )


def test_pydantic_invalid_sandbox_name():
    """sandbox_name must adhere to ^sbx-[a-z0-9]{8,}$."""
    with pytest.raises(ValueError, match="sandbox_name must match"):
        RunCreate(
            run_id="test-run-bad",
            sandbox_name="my-custom-vm",
        )


def test_pydantic_invalid_state():
    """state must be one of the permitted lifecycle states."""
    with pytest.raises(ValueError, match="state must be one of"):
        RunCreate(
            run_id="test-run-bad",
            sandbox_name="sbx-1234abcd",
            state="flying",
        )


def test_serve_report_not_found(client):
    """GET /reports/nonexistent returns 404."""
    resp = client.get("/reports/definitely_not_existing_report.json")
    assert resp.status_code == 404


def test_serve_report_traversal_blocked(client):
    """Path traversal attempt returns 403 or 404."""
    resp = client.get("/reports/../../app.py")
    assert resp.status_code in (403, 404)
