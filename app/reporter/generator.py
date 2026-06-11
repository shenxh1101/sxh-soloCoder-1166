import json
import time
from dataclasses import asdict
from app.models import Anomaly
from app.analyzer.detector import aggregate_by_severity


def deduplicate_anomalies(anomalies: list[Anomaly]) -> tuple[list[Anomaly], int]:
    seen = set()
    deduped = []
    skipped = 0
    for a in anomalies:
        fp = a.request_data.get("field_path", "")
        cat = a.category
        key = (fp, cat)
        if key in seen:
            skipped += 1
            continue
        seen.add(key)
        deduped.append(a)
    return deduped, skipped


def compute_request_diff(
    original_request: dict | None, mutated_request: dict | None
) -> dict:
    if not original_request or not mutated_request:
        return {}

    changes = []

    orig_url = original_request.get("url", "")
    mut_url = mutated_request.get("url", "")
    if orig_url != mut_url:
        changes.append({
            "location": "url",
            "original": orig_url,
            "mutated": mut_url,
        })

    orig_qp = original_request.get("query_params", {})
    mut_qp = mutated_request.get("query_params", {})
    for k in set(list(orig_qp.keys()) + list(mut_qp.keys())):
        ov = orig_qp.get(k)
        mv = mut_qp.get(k)
        if str(ov) != str(mv):
            changes.append({
                "location": f"query>{k}",
                "original": str(ov),
                "mutated": str(mv),
            })

    orig_body = original_request.get("body", "")
    mut_body = mutated_request.get("body", "")
    if orig_body != mut_body:
        orig_parsed = _try_parse_json(orig_body)
        mut_parsed = _try_parse_json(mut_body)
        if orig_parsed and mut_parsed:
            _diff_json_fields(orig_parsed, mut_parsed, "body", changes)
        else:
            changes.append({
                "location": "body",
                "original": (orig_body or "")[:500],
                "mutated": (mut_body or "")[:500],
            })

    orig_headers = original_request.get("headers", {})
    mut_headers = mutated_request.get("headers", {})
    for k in set(list(orig_headers.keys()) + list(mut_headers.keys())):
        ov = orig_headers.get(k)
        mv = mut_headers.get(k)
        if str(ov) != str(mv):
            changes.append({
                "location": f"header>{k}",
                "original": str(ov),
                "mutated": str(mv),
            })

    orig_method = original_request.get("method", "")
    mut_method = mutated_request.get("method", "")
    if orig_method and mut_method and orig_method != mut_method:
        changes.append({
            "location": "method",
            "original": orig_method,
            "mutated": mut_method,
        })

    return {"field_changes": changes, "change_count": len(changes)}


def _try_parse_json(s: str | None) -> dict | None:
    if not s:
        return None
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return None


def _diff_json_fields(
    orig: dict | list,
    mutated: dict | list,
    prefix: str,
    changes: list,
):
    if isinstance(orig, dict) and isinstance(mutated, dict):
        for k in set(list(orig.keys()) + list(mutated.keys())):
            ov = orig.get(k)
            mv = mutated.get(k)
            path = f"{prefix}>{k}"
            if isinstance(ov, (dict, list)) and isinstance(mv, (dict, list)):
                _diff_json_fields(ov, mv, path, changes)
            elif str(ov) != str(mv):
                changes.append({
                    "location": path,
                    "original": json.dumps(ov, ensure_ascii=False),
                    "mutated": json.dumps(mv, ensure_ascii=False),
                })
    elif isinstance(orig, list) and isinstance(mutated, list):
        max_len = max(len(orig), len(mutated))
        for i in range(max_len):
            ov = orig[i] if i < len(orig) else None
            mv = mutated[i] if i < len(mutated) else None
            path = f"{prefix}[{i}]"
            if isinstance(ov, (dict, list)) and isinstance(mv, (dict, list)):
                _diff_json_fields(ov, mv, path, changes)
            elif str(ov) != str(mv):
                changes.append({
                    "location": path,
                    "original": json.dumps(ov, ensure_ascii=False),
                    "mutated": json.dumps(mv, ensure_ascii=False),
                })


def generate_report(
    task_id: str,
    base_requests: list,
    results: list,
    anomalies: list[Anomaly],
    config: dict,
    start_time: float,
    end_time: float,
    baseline: dict | None = None,
    dedup_skipped: int = 0,
) -> dict:
    deduped, skipped = deduplicate_anomalies(anomalies)
    total_skipped = dedup_skipped + skipped

    severity_counts = aggregate_by_severity(deduped)

    anomaly_by_category = {}
    for a in deduped:
        cat = a.category
        if cat not in anomaly_by_category:
            anomaly_by_category[cat] = []
        anomaly_by_category[cat].append(asdict(a))

    status_distribution = {}
    response_times = []
    for r in results:
        sc = r.get("status_code") or 0
        status_distribution[sc] = status_distribution.get(sc, 0) + 1
        if r.get("response_time_ms"):
            response_times.append(r["response_time_ms"])

    avg_response_time = sum(response_times) / len(response_times) if response_times else 0
    max_response_time = max(response_times) if response_times else 0
    min_response_time = min(response_times) if response_times else 0

    top_anomalies = sorted(
        [asdict(a) for a in deduped],
        key=lambda x: {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(
            x["severity"], 0
        ),
        reverse=True,
    )[:50]

    baseline_summary = None
    if baseline:
        baseline_summary = {
            "status_code": baseline.get("status_code"),
            "response_time_ms": baseline.get("response_time_ms"),
            "error": baseline.get("error"),
        }

    report = {
        "task_id": task_id,
        "generated_at": time.time(),
        "duration_seconds": round(end_time - start_time, 2),
        "summary": {
            "total_requests": len(results),
            "base_samples": len(base_requests),
            "total_anomalies_raw": len(anomalies),
            "total_anomalies_deduped": len(deduped),
            "dedup_skipped": total_skipped,
            "severity_breakdown": severity_counts,
            "status_distribution": status_distribution,
            "avg_response_time_ms": round(avg_response_time, 2),
            "max_response_time_ms": round(max_response_time, 2),
            "min_response_time_ms": round(min_response_time, 2),
        },
        "config": config,
        "baseline": baseline_summary,
        "anomalies_by_category": anomaly_by_category,
        "top_anomalies": top_anomalies,
        "recommendations": _generate_recommendations(deduped, severity_counts),
    }

    return report


def filter_anomalies(
    anomalies: list[Anomaly],
    field_path: str | None = None,
    mutation_type: str | None = None,
    status_code_min: int | None = None,
    status_code_max: int | None = None,
    severity: list[str] | None = None,
    category: list[str] | None = None,
) -> list[Anomaly]:
    filtered = []
    for a in anomalies:
        if severity and a.severity not in severity:
            continue
        if category and a.category not in category:
            continue
        if field_path:
            fp = a.request_data.get("field_path", "")
            if field_path.lower() not in fp.lower():
                continue
        if mutation_type:
            mt = a.request_data.get("mutation_type", "")
            if mutation_type.lower() not in mt.lower():
                continue
        if status_code_min is not None:
            sc = a.response_data.get("status_code") or 0
            if sc < status_code_min:
                continue
        if status_code_max is not None:
            sc = a.response_data.get("status_code") or 0
            if sc > status_code_max:
                continue
        filtered.append(a)
    return filtered


def _generate_recommendations(anomalies: list, severity_counts: dict) -> list[str]:
    recommendations = []

    if severity_counts.get("critical", 0) > 0:
        recommendations.append(
            f"发现 {severity_counts['critical']} 个严重漏洞，建议立即修复。"
        )

    if any(a.category == "blacklist_match" for a in anomalies):
        blacklist_count = len([a for a in anomalies if a.category == "blacklist_match"])
        recommendations.append(
            f"发现 {blacklist_count} 个响应暴露了敏感错误信息。"
            "建议对生产环境关闭详细错误信息输出。"
        )

    if any(a.category == "timeout" for a in anomalies):
        timeout_count = len([a for a in anomalies if a.category == "timeout"])
        recommendations.append(
            f"发现 {timeout_count} 个请求超时，可能存在拒绝服务漏洞或资源耗尽问题。"
        )

    if any(a.category == "500_error" for a in anomalies):
        count_500 = len([a for a in anomalies if a.category == "500_error"])
        recommendations.append(
            f"发现 {count_500} 个500内部服务器错误，"
            "存在输入验证不足导致的未处理异常。建议增强输入过滤和错误处理。"
        )

    if any(a.category == "slow_response" for a in anomalies):
        slow_count = len([a for a in anomalies if a.category == "slow_response"])
        recommendations.append(
            f"发现 {slow_count} 个响应时间异常增长的请求，"
            "可能存在SQL注入、正则ReDoS或资源密集型操作。"
        )

    if any(a.category == "connection_error" for a in anomalies):
        conn_count = len([a for a in anomalies if a.category == "connection_error"])
        recommendations.append(
            f"发现 {conn_count} 个连接错误，输入可能导致服务端崩溃或拒绝连接。"
        )

    return recommendations


def export_anomaly_requests(
    anomalies: list[Anomaly],
    severity_filter: list[str] | None = None,
    category_filter: list[str] | None = None,
) -> list[dict]:
    test_cases = []
    for i, a in enumerate(anomalies):
        if severity_filter and a.severity not in severity_filter:
            continue
        if category_filter and a.category not in category_filter:
            continue

        tc = {
            "id": i + 1,
            "severity": a.severity.value if hasattr(a.severity, 'value') else a.severity,
            "category": a.category,
            "trigger_reason": a.description,
            "response_time_ms": a.response_time_ms,
            "response_evidence": a.response_data,
            "request": a.request_data,
            "baseline": {
                "status_code": a.response_data.get("baseline_status_code"),
                "response_time_ms": a.response_data.get("baseline_response_time_ms"),
                "error": a.response_data.get("baseline_error"),
            },
        }
        test_cases.append(tc)

    return test_cases


def format_har_compatible(test_cases: list[dict]) -> dict:
    entries = []
    for tc in test_cases:
        req = tc["request"]
        entry = {
            "request": {
                "method": req.get("method", "GET"),
                "url": req.get("url", ""),
                "headers": [
                    {"name": k, "value": v} for k, v in req.get("headers", {}).items()
                ],
                "postData": {"text": req.get("body", "")} if req.get("body") else {},
            },
            "response": {},
            "_meta": {
                "test_case_id": tc["id"],
                "severity": tc["severity"],
                "category": tc["category"],
                "trigger_reason": tc["trigger_reason"],
            },
        }
        entries.append(entry)

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "FuzzHarvester"},
            "entries": entries,
        }
    }


def format_curl_commands(test_cases: list[dict]) -> str:
    lines = []
    for tc in test_cases:
        req = tc["request"]
        method = req.get("method", "GET")
        url = req.get("url", "")
        body = req.get("body", "")
        headers = req.get("headers", {})

        cmd_parts = ["curl", "-X", method]
        for h_name, h_value in headers.items():
            cmd_parts.append("-H")
            cmd_parts.append(f'"{h_name}: {h_value}"')
        if body:
            escaped_body = body.replace("\\", "\\\\").replace('"', '\\"')
            cmd_parts.append("-d")
            cmd_parts.append(f'"{escaped_body}"')
        cmd_parts.append(f'"{url}"')

        line = " \\\n  ".join(cmd_parts)
        lines.append(
            f"# TC-{tc['id']} [{tc['severity']}] {tc['category']}: {tc['trigger_reason']}\n{line}"
        )

    return "\n\n".join(lines)


def format_pytest_script(test_cases: list[dict], task=None) -> str:
    script = '''"""
回归测试 — 由 FuzzHarvester 自动生成
每个用例携带基线信息，可直接用于 CI 回归。
"""
import requests
import pytest


BASE_TIMEOUT = 30

'''
    for i, tc in enumerate(test_cases):
        req = tc["request"]
        method = req.get("method", "GET")
        url = req.get("url", "")
        body = req.get("body", "")
        headers = req.get("headers", {})
        severity = tc["severity"]
        category = tc["category"]
        reason = tc["trigger_reason"]
        baseline = tc.get("baseline", {})
        mutated_sc = tc.get("response_evidence", {}).get("status_code")
        mutated_latency = tc.get("response_time_ms")
        baseline_sc = baseline.get("status_code")
        baseline_latency = baseline.get("response_time_ms")

        safe_name = f"tc_{i+1:03d}_{severity}_{category}"
        safe_name = ''.join(c if c.isalnum() else '_' for c in safe_name)

        docstring_lines = []
        if baseline_sc is not None:
            docstring_lines.append(f"基线: status={baseline_sc}, latency={baseline_latency}ms")
        if mutated_sc is not None:
            docstring_lines.append(f"变异: status={mutated_sc}, latency={mutated_latency}ms")
        docstring_lines.append(f"[{severity}] {category}: {reason}")
        docstring = " | ".join(docstring_lines)

        script += f'''
@pytest.mark.{severity}
@pytest.mark.{category}
def test_{safe_name}():
    """{docstring}"""
    resp = requests.{method.lower()}(
        "{url}",
        headers={json.dumps(headers)},
'''
        if body:
            script += f'        data={json.dumps(body)},\n'
        script += f'''        timeout=BASE_TIMEOUT,
    )
    assert resp.status_code < 500, (
        f"Server error {{resp.status_code}}: {{resp.text[:200]}}"
    )
'''

        if baseline_sc is not None and mutated_sc is not None and baseline_sc != mutated_sc:
            script += f'''    assert resp.status_code == {baseline_sc}, (
        f"回归异常! 基线状态码={{ {baseline_sc} }}, 当前状态码={{resp.status_code}} (曾触发{mutated_sc})"
    )
'''

    return script