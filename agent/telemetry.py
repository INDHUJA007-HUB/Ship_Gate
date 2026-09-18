import boto3
import time
import re
from agent.orchestration.v1_contracts import RuntimeEvidenceV1

class TelemetryError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code

class TelemetryService:
    def __init__(self, xray_client=None, logs_client=None):
        self.xray = xray_client or boto3.client('xray')
        self.logs = logs_client or boto3.client('logs')

    def redact(self, text: str) -> str:
        text = re.sub(r'(?i)AKIA[0-9A-Z]{16}', 'AKIA[REDACTED]', text)
        text = re.sub(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', '[REDACTED_JWT]', text)
        return text

    def collect_evidence(self, tenant_id: str, trace_id: str, start_time: int, end_time: int, log_group: str) -> RuntimeEvidenceV1:
        try:
            trace_resp = self.xray.batch_get_traces(TraceIds=[trace_id])
        except Exception as e:
            if "LimitExceeded" in str(e):
                raise TelemetryError("xray_cost_bound", str(e))
            raise TelemetryError("xray_denied", str(e))
        
        traces = trace_resp.get('Traces', [])
        if not traces:
            return RuntimeEvidenceV1(
                schema_version="1.0",
                tenant_id=tenant_id,
                trace_id=trace_id,
                time_window_start=start_time,
                time_window_end=end_time,
                status="unavailable",
                failing_hop=None,
                redacted_logs=[]
            )
        
        failing_hop = None
        for trace in traces:
            for segment in trace.get('Segments', []):
                doc = segment.get('Document', '{}')
                if '"error":true' in doc or '"fault":true' in doc:
                    match = re.search(r'"name":"([^"]+)"', doc)
                    if match:
                        failing_hop = match.group(1)
                        break
            if failing_hop:
                break
        
        try:
            query_id = self.logs.start_query(
                logGroupName=log_group,
                startTime=start_time - 300,
                endTime=end_time + 300,
                queryString="fields @timestamp, @message | filter @message like /ERROR/ | limit 100"
            )['queryId']
        except Exception as e:
            if "LimitExceeded" in str(e):
                raise TelemetryError("logs_cost_bound", str(e))
            raise TelemetryError("logs_denied", str(e))
            
        status = 'Running'
        max_attempts = 10
        attempts = 0
        res = {}
        while status in ['Running', 'Scheduled'] and attempts < max_attempts:
            time.sleep(2)
            attempts += 1
            res = self.logs.get_query_results(queryId=query_id)
            status = res['status']
            
        if status != 'Complete':
            raise TelemetryError("logs_timeout", "CloudWatch Logs Insights query timed out.")
            
        raw_logs = []
        total_size = 0
        MAX_SIZE = 100 * 1024 
        
        for row in res.get('results', []):
            msg = next((f['value'] for f in row if f['field'] == '@message'), '')
            if msg:
                redacted = self.redact(msg)
                size = len(redacted.encode('utf-8'))
                if total_size + size > MAX_SIZE:
                    raw_logs.append("[TRUNCATED: SIZE LIMIT EXCEEDED]")
                    break
                raw_logs.append(redacted)
                total_size += size
                
        return RuntimeEvidenceV1(
            schema_version="1.0",
            tenant_id=tenant_id,
            trace_id=trace_id,
            time_window_start=start_time,
            time_window_end=end_time,
            status="evidence_ready",
            failing_hop=failing_hop,
            redacted_logs=raw_logs
        )
