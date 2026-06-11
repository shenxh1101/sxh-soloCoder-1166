import re

from app.models import Anomaly, Severity


DEFAULT_BLACKLIST = [
    "SQL syntax",
    "MySQL server",
    "ORA-",
    "PostgreSQL",
    "Unclosed quotation",
    "Syntax error",
    "stack trace",
    "traceback",
    "FileNotFoundException",
    "NullReferenceException",
    "Segmentation fault",
    "core dumped",
    "memory leak",
    "undefined index",
    "Notice: ",
    "Warning: ",
    "Error: ",
    "<script>",
    "onerror",
]

DEFAULT_ERROR_CODES = {
    "500": Severity.CRITICAL,
    "502": Severity.HIGH,
    "503": Severity.MEDIUM,
    "504": Severity.MEDIUM,
    "400": Severity.LOW,
    "401": Severity.INFO,
    "403": Severity.INFO,
    "404": Severity.INFO,
}


def analyze_response(
    result: dict,
    blacklist: list[str] | None = None,
    slow_threshold_ms: int = 5000,
    base_response_time: float | None = None,
) -> list[Anomaly]:
    anomalies = []

    status_code = result.get("status_code")
    resp_time = result.get("response_time_ms", 0)
    resp_body = result.get("response_body", "") or ""
    error = result.get("error")

    if error:
        if error == "timeout":
            a = Anomaly(
                severity=Severity.HIGH,
                category="timeout",
                description=f"Request timed out ({int(slow_threshold_ms / 1000)}s threshold)",
                request_data=result.get("mutated_request", {}),
                response_data={
                    "status_code": status_code,
                    "error": error,
                    "response_time_ms": resp_time,
                },
                response_time_ms=resp_time,
            )
            anomalies.append(a)
        else:
            a = Anomaly(
                severity=Severity.MEDIUM,
                category="connection_error",
                description=f"Connection error: {error}",
                request_data=result.get("mutated_request", {}),
                response_data={"error": error, "response_time_ms": resp_time},
                response_time_ms=resp_time,
            )
            anomalies.append(a)

    if status_code and status_code >= 500:
        if status_code == 500:
            severity = Severity.CRITICAL
        elif status_code == 502:
            severity = Severity.HIGH
        elif status_code == 504:
            severity = Severity.HIGH
        else:
            severity = Severity.HIGH
        a = Anomaly(
            severity=severity,
            category=f"{status_code}_error",
            description=f"Server returned {status_code} status code",
            request_data=result.get("mutated_request", {}),
            response_data={
                "status_code": status_code,
                "response_time_ms": resp_time,
                "response_body_prefix": (resp_body[:200] if resp_body else ""),
            },
            response_time_ms=resp_time,
        )
        anomalies.append(a)

    if base_response_time is not None and base_response_time > 0:
        threshold = base_response_time * 5
        if resp_time > threshold and resp_time > 500:
            a = Anomaly(
                severity=Severity.MEDIUM,
                category="slow_response",
                description=f"Response time {resp_time}ms is > {int(threshold)}ms (base {int(base_response_time)}ms * 5)",
                request_data=result.get("mutated_request", {}),
                response_data={
                    "status_code": status_code,
                    "response_time_ms": resp_time,
                    "base_time": base_response_time,
                },
                response_time_ms=resp_time,
            )
            anomalies.append(a)
    elif resp_time > slow_threshold_ms:
        a = Anomaly(
            severity=Severity.MEDIUM,
            category="slow_response",
            description=f"Response time {resp_time}ms exceeded threshold {slow_threshold_ms}ms",
            request_data=result.get("mutated_request", {}),
            response_data={
                "status_code": status_code,
                "response_time_ms": resp_time,
            },
            response_time_ms=resp_time,
        )
        anomalies.append(a)

    if resp_body:
        if blacklist is None:
            blacklist = DEFAULT_BLACKLIST.copy()

        matched = find_blacklist_matches(resp_body, blacklist)
        for pattern, match_text in matched:
            a = Anomaly(
                severity=Severity.CRITICAL,
                category="blacklist_match",
                description=f"Response contains sensitive error information (keyword: {pattern})",
                request_data=result.get("mutated_request", {}),
                response_data={
                    "matched_keyword": pattern,
                    "matched_text": match_text[:100],
                    "status_code": status_code,
                    "response_time_ms": resp_time,
                },
                response_time_ms=resp_time,
            )
            anomalies.append(a)

    return anomalies


def find_blacklist_matches(body: str, patterns: list[str]) -> list[tuple[str, str]]:
    matches = []
    for pattern in patterns:
        if not pattern.strip():
            continue
        try:
            for match in re.finditer(pattern, body, re.IGNORECASE):
                start = max(0, match.start() - 20)
                end = min(len(body), match.end() + 20)
                context = body[start:end]
                matches.append((pattern, context))
        except re.error:
            if pattern.lower() in body.lower():
                idx = body.lower().find(pattern.lower())
                start = max(0, idx - 20)
                end = min(len(body), idx + len(pattern) + 20)
                context = body[start:end]
                matches.append((pattern, context))
    return matches


def aggregate_by_severity(anomalies: list[Anomaly]) -> dict[str, int]:
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for a in anomalies:
        counts[a.severity] += 1
    return counts