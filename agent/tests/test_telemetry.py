import pytest
from unittest.mock import MagicMock
from agent.telemetry import TelemetryService, TelemetryError

@pytest.fixture
def mock_xray():
    return MagicMock()

@pytest.fixture
def mock_logs():
    return MagicMock()

@pytest.fixture
def telemetry_service(mock_xray, mock_logs):
    return TelemetryService(xray_client=mock_xray, logs_client=mock_logs)

def test_telemetry_redaction(telemetry_service):
    raw = "Failed to connect AKIAIOSFODNN7EXAMPLE and token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    redacted = telemetry_service.redact(raw)
    assert "AKIA[REDACTED]" in redacted
    assert "[REDACTED_JWT]" in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted

def test_telemetry_unsampled(telemetry_service, mock_xray, mock_logs):
    mock_xray.batch_get_traces.return_value = {"Traces": []}
    result = telemetry_service.collect_evidence("t-1", "trace-1", 100, 200, "log_group")
    assert result.status == "unavailable"
    mock_logs.start_query.assert_not_called()

def test_telemetry_success_and_size_limit(telemetry_service, mock_xray, mock_logs):
    mock_xray.batch_get_traces.return_value = {
        "Traces": [{
            "Segments": [{"Document": '{"name":"failing-hop", "error":true}'}]
        }]
    }
    
    mock_logs.start_query.return_value = {"queryId": "q1"}
    large_msg = "x" * 60000 
    
    mock_logs.get_query_results.return_value = {
        "status": "Complete",
        "results": [
            [{"field": "@message", "value": large_msg}],
            [{"field": "@message", "value": large_msg}] 
        ]
    }
    
    result = telemetry_service.collect_evidence("t-1", "trace-1", 100, 200, "log_group")
    assert result.status == "evidence_ready"
    assert result.failing_hop == "failing-hop"
    assert len(result.redacted_logs) == 2
    assert result.redacted_logs[-1] == "[TRUNCATED: SIZE LIMIT EXCEEDED]"

def test_collect_evidence_expands_time_window(telemetry_service, mock_xray, mock_logs):
    mock_xray.batch_get_traces.return_value = {
        "Traces": [{
            "Segments": [{"Document": '{"name":"failing-hop", "error":true}'}]
        }]
    }
    mock_logs.start_query.return_value = {"queryId": "q123"}
    mock_logs.get_query_results.return_value = {"status": "Complete", "results": []}
    
    telemetry_service.collect_evidence("tenant-123", "trace-123", 1000, 2000, "my-log-group")
    
    mock_logs.start_query.assert_called_once()
    kwargs = mock_logs.start_query.call_args.kwargs
    assert kwargs["startTime"] == 700
    assert kwargs["endTime"] == 2300
