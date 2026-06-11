import json
import time
from dataclasses import asdict
from app.models import Anomaly
from app.analyzer.detector import aggregate_by_severity


def generate_report(
    task_id: str,
    base_requests: list,
    results: list,
    anomalies: list[Anomaly],
    config: dict,
    start_time: float,
    end_time: float,
) -> dict:
    severity_counts = aggregate_by_severity(anomalies)

    anomaly_by_category = {}
    for a in anomalies:
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
        [asdict(a) for a in anomalies],
        key=lambda x: {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(
            x["severity"], 0
        ),
        reverse=True,
    )[:50]

    report = {
        "task_id": task_id,
        "generated_at": time.time(),
        "duration_seconds": round(end_time - start_time, 2),
        "summary": {
            "total_requests": len(results),
            "base_samples": len(base_requests),
            "total_anomalies": len(anomalies),
            "severity_breakdown": severity_counts,
            "status_distribution": status_distribution,
            "avg_response_time_ms": round(avg_response_time, 2),
            "max_response_time_ms": round(max_response_time, 2),
            "min_response_time_ms": round(min_response_time, 2),
        },
        "config": config,
        "anomalies_by_category": anomaly_by_category,
        "top_anomalies": top_anomalies,
        "recommendations": _generate_recommendations(anomalies, severity_counts),
    }

    return report


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
            "severity": a.severity,
            "category": a.category,
            "trigger_reason": a.description,
            "response_time_ms": a.response_time_ms,
            "response_evidence": a.response_data,
            "request": a.request_data,
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