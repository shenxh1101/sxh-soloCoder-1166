import json
import time
import threading
from dataclasses import asdict
from flask import Blueprint, request, jsonify

from app.models import (
    TaskStatus,
    create_task,
    get_task,
    list_tasks,
)
from app.parser.parsers import parse_har, parse_curl
from app.mutator.engine import generate_mutations
from app.sender.concurrent import send_batch, send_request
from app.analyzer.detector import analyze_response
from app.reporter.generator import (
    generate_report,
    filter_anomalies,
    export_anomaly_requests,
    compute_request_diff,
    format_har_compatible,
    format_curl_commands,
    format_pytest_script,
)
from app import storage

api = Blueprint("api", __name__)


def _save_task_if_alive(task):
    if not task._stopped:
        storage.save_task(task)


def _collect_baseline(task):
    if task.baseline is not None:
        return
    config = task.config
    baseline_all = {}
    for br in task.base_requests:
        if task._stopped:
            return
        resp = send_request(
            method=br.get("method", "GET"),
            url=br["url"],
            headers=br.get("headers"),
            body=br.get("body"),
            timeout=config.get("timeout", 30),
        )
        baseline_all[br["url"]] = resp
    task.baseline = baseline_all
    _save_task_if_alive(task)


def _run_fuzz_background(task):
    if task.status != TaskStatus.RUNNING:
        return

    config = task.config
    base_requests = task.base_requests

    if task.baseline is None:
        task.progress["phase"] = "baseline"
        task.updated_at = time.time()
        _collect_baseline(task)
        if task._stopped:
            return

    if not task.all_mutations:
        all_mutations = []
        for br in base_requests:
            if task._stopped:
                return
            while task.status == TaskStatus.PAUSED:
                task.progress["phase"] = "paused"
                task.updated_at = time.time()
                _save_task_if_alive(task)
                task._pause_event.wait()
                if task._stopped:
                    return
                task.progress["phase"] = "generating"
            muts = generate_mutations(
                br,
                max_depth=config.get("max_depth", "top_level"),
                enabled_strategies=config.get("enabled_strategies"),
                target_locations=config.get("target_locations"),
                max_mutations_per_field=config.get("max_mutations_per_field"),
            )
            all_mutations.extend(muts)
        task.all_mutations = all_mutations
        task.progress["total_mutations"] = len(all_mutations)

    task.progress["phase"] = "sending"
    task.updated_at = time.time()

    concurrency = config.get("concurrency", 10)
    batch_size = concurrency * 2
    send_start = time.time()
    total = len(task.all_mutations)
    results = task.results
    anomalies = task.anomalies

    url = base_requests[0].get("url", "") if base_requests else ""
    baseline_resp = (task.baseline or {}).get(url, {})
    base_resp_time = baseline_resp.get("response_time_ms") if baseline_resp else None

    for i in range(task.sent_count, total, batch_size):
        if task._stopped:
            task.progress["phase"] = "cancelled"
            return
        if task.status == TaskStatus.PAUSED:
            task.progress["phase"] = "paused"
            task.updated_at = time.time()
            _save_task_if_alive(task)
            task._pause_event.wait()
            if task._stopped:
                return
            task.progress["phase"] = "sending"
            continue

        batch_end = min(i + batch_size, total)
        batch = task.all_mutations[i:batch_end]
        batch_results = send_batch(
            batch,
            concurrency=concurrency,
            timeout=config.get("timeout", 30),
        )
        if task._stopped:
            return
        results.extend(batch_results)

        task.progress["phase"] = "analyzing"
        for br_result in batch_results:
            br_result_anomalies = analyze_response(
                br_result,
                blacklist=config.get("blacklist"),
                slow_threshold_ms=config.get("slow_threshold_ms", 5000),
                base_response_time=base_resp_time,
            )
            for anom in br_result_anomalies:
                anom.request_data["mutation_type"] = br_result.get("mutation_type", "")
                anom.request_data["field_path"] = br_result.get("field_path", "")
                anom.request_data["mutation_desc"] = br_result.get("mutation_desc", "")
                anom.request_data["mutated_value"] = br_result.get("mutated_value", "")
                anom.request_data["original_request"] = br_result.get(
                    "original_request", {}
                )
            anomalies.extend(br_result_anomalies)

        task.sent_count = batch_end
        task.progress["sent"] = batch_end
        task.progress["anomalies_found"] = len(anomalies)
        task.progress["phase"] = "sending"

        elapsed = time.time() - send_start
        if batch_end > 0 and elapsed > 0:
            rate = batch_end / elapsed
            remaining = total - batch_end
            if rate > 0:
                task.progress["estimated_seconds_remaining"] = round(remaining / rate)

        task.updated_at = time.time()
        _save_task_if_alive(task)

    task.results = results
    task.anomalies = anomalies

    task.progress["phase"] = "reporting"
    task.updated_at = time.time()

    report = generate_report(
        task_id=task.task_id,
        base_requests=base_requests,
        results=results,
        anomalies=list(anomalies),
        config=config,
        start_time=task.created_at,
        end_time=time.time(),
        baseline=baseline_resp,
        dedup_skipped=task.dedup_skipped,
    )
    task.report = report
    task.status = TaskStatus.COMPLETED

    task.progress["phase"] = task.status.value
    task.progress["estimated_seconds_remaining"] = 0
    task.updated_at = time.time()
    _save_task_if_alive(task)


@api.route("/api/upload", methods=["POST"])
def upload_samples():
    if "file" in request.files:
        f = request.files["file"]
        content = f.read().decode("utf-8")
        filename = f.filename or ""

        if filename.endswith(".har"):
            try:
                base_requests = parse_har(content)
            except Exception as e:
                return jsonify({"error": f"HAR解析失败: {str(e)}"}), 400
        elif filename.endswith(".txt"):
            try:
                base_requests = parse_curl(content)
            except Exception as e:
                return jsonify({"error": f"CURL解析失败: {str(e)}"}), 400
        else:
            return jsonify({"error": "不支持的文件格式，请上传 .har 或 .txt 文件"}), 400

        parsed = [vars(req) for req in base_requests]
        return jsonify({"count": len(parsed), "requests": parsed})

    body = request.get_json(silent=True)
    if body:
        sample_type = body.get("type", "har")
        raw = body.get("content", "")
        if sample_type == "har":
            try:
                base_requests = parse_har(raw)
            except Exception as e:
                return jsonify({"error": f"HAR解析失败: {str(e)}"}), 400
        elif sample_type == "curl":
            try:
                base_requests = parse_curl(raw)
            except Exception as e:
                return jsonify({"error": f"CURL解析失败: {str(e)}"}), 400
        else:
            return jsonify({"error": "type必须为 'har' 或 'curl'"}), 400

        parsed = [vars(req) for req in base_requests]
        return jsonify({"count": len(parsed), "requests": parsed})

    return jsonify({"error": "请上传文件或提供JSON body"}), 400


@api.route("/api/fuzz/start", methods=["POST"])
def start_fuzz():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "请求体需要JSON格式"}), 400

    samples = data.get("samples")
    if not samples:
        return jsonify({"error": "缺少基础请求样本"}), 400

    config = {
        "max_depth": data.get("max_depth", "top_level"),
        "concurrency": data.get("concurrency", 10),
        "timeout": data.get("timeout", 30),
        "slow_threshold_ms": data.get("slow_threshold_ms", 5000),
        "blacklist": data.get("blacklist", None),
        "enabled_strategies": data.get("enabled_strategies", None),
        "target_locations": data.get("target_locations", None),
        "max_mutations_per_field": data.get("max_mutations_per_field", None),
    }

    if "target_locations" in config and config["target_locations"] is None:
        config["target_locations"] = ["query", "path", "body"]

    task = create_task(config, samples)
    task.status = TaskStatus.RUNNING
    storage.save_task(task)

    thread = threading.Thread(target=_run_fuzz_background, args=(task,), daemon=True)
    task._thread = thread
    thread.start()
    task._pause_event.set()

    return jsonify({
        "task_id": task.task_id,
        "status": TaskStatus.RUNNING.value,
        "message": "任务已启动，后台异步执行中",
    })


@api.route("/api/fuzz/tasks/<task_id>/pause", methods=["POST"])
def pause_task(task_id):
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404

    if task.status != TaskStatus.RUNNING:
        return jsonify({"error": f"任务当前状态为 {task.status.value}，无法暂停"}), 400

    task.status = TaskStatus.PAUSED
    task.progress["phase"] = "paused"
    task._pause_event.clear()
    task.updated_at = time.time()
    storage.save_task(task)
    return jsonify({"task_id": task_id, "status": "paused", "progress": task.progress})


@api.route("/api/fuzz/tasks/<task_id>/resume", methods=["POST"])
def resume_task(task_id):
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404

    if task.status != TaskStatus.PAUSED:
        return jsonify({"error": f"任务当前状态为 {task.status.value}，无法恢复"}), 400

    task.status = TaskStatus.RUNNING
    task.progress["phase"] = "resuming"
    task._pause_event.set()
    task.updated_at = time.time()
    return jsonify({
        "task_id": task_id,
        "status": "running",
        "progress": task.progress,
        "message": f"任务已恢复，将从第 {task.sent_count + 1} 条变异继续",
    })


@api.route("/api/fuzz/tasks/<task_id>/retry", methods=["POST"])
def retry_task(task_id):
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404

    task._stopped = True
    task._pause_event.set()
    old_thread = task._thread
    if old_thread and old_thread.is_alive():
        old_thread.join(timeout=2)

    task._stopped = False
    task.sent_count = 0
    task.results = []
    task.anomalies = []
    task.all_mutations = []
    task.report = {}
    task.baseline = None
    task.dedup_skipped = 0
    task.status = TaskStatus.RUNNING
    task.progress = {
        "total_mutations": 0,
        "sent": 0,
        "anomalies_found": 0,
        "phase": "generating",
        "estimated_seconds_remaining": None,
        "started_at": time.time(),
    }
    task._pause_event.set()
    thread = threading.Thread(target=_run_fuzz_background, args=(task,), daemon=True)
    task._thread = thread
    thread.start()
    task.updated_at = time.time()
    storage.save_task(task)

    return jsonify({
        "task_id": task_id,
        "status": "running",
        "progress": task.progress,
        "message": "任务已重置，旧线程已停止，从头开始重试",
    })


@api.route("/api/fuzz/tasks/<task_id>/status", methods=["GET"])
def task_status(task_id):
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404

    return jsonify({
        "task_id": task.task_id,
        "status": task.status.value,
        "progress": task.progress,
        "created_at": task.created_at,
        "updated_at": task.updated_at,
    })


@api.route("/api/fuzz/tasks/<task_id>/report", methods=["GET"])
def task_report(task_id):
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404

    if task.status != TaskStatus.COMPLETED:
        return jsonify({
            "task_id": task.task_id,
            "status": task.status.value,
            "progress": task.progress,
            "baseline": task.baseline,
            "message": "任务尚未完成，暂无报告",
        })

    return jsonify(task.report)


def _parse_anomaly_filters():
    field_path = request.args.get("field_path") or (request.get_json(silent=True) or {}).get("field_path")
    mutation_type = request.args.get("mutation_type") or (request.get_json(silent=True) or {}).get("mutation_type")
    status_code_min = request.args.get("status_code_min", type=int)
    status_code_max = request.args.get("status_code_max", type=int)

    if status_code_min is None:
        body = request.get_json(silent=True) or {}
        status_code_min = body.get("status_code_min")
    if status_code_max is None:
        body = request.get_json(silent=True) or {}
        status_code_max = body.get("status_code_max")

    severity = request.args.get("severity")
    if not severity:
        body = request.get_json(silent=True) or {}
        severity = body.get("severity")
    if severity and isinstance(severity, str):
        severity = [s.strip() for s in severity.split(",")]

    category = request.args.get("category")
    if not category:
        body = request.get_json(silent=True) or {}
        category = body.get("category")
    if category and isinstance(category, str):
        category = [c.strip() for c in category.split(",")]

    return field_path, mutation_type, status_code_min, status_code_max, severity, category


@api.route("/api/fuzz/tasks/<task_id>/anomalies", methods=["GET"])
def task_anomalies(task_id):
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404

    (field_path, mutation_type, status_code_min,
     status_code_max, severity, category) = _parse_anomaly_filters()

    filtered = filter_anomalies(
        task.anomalies,
        field_path=field_path,
        mutation_type=mutation_type,
        status_code_min=status_code_min,
        status_code_max=status_code_max,
        severity=severity,
        category=category,
    )

    return jsonify({
        "task_id": task.task_id,
        "total": len(task.anomalies),
        "filtered_count": len(filtered),
        "filters": {
            "field_path": field_path,
            "mutation_type": mutation_type,
            "status_code_min": status_code_min,
            "status_code_max": status_code_max,
            "severity": severity,
            "category": category,
        },
        "anomalies": [asdict(a) for a in filtered],
    })


@api.route("/api/fuzz/tasks/<task_id>/anomaly/<int:index>", methods=["GET"])
def get_anomaly_detail(task_id, index):
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404

    if index < 0 or index >= len(task.anomalies):
        return jsonify({"error": "异常索引超出范围"}), 404

    anom = task.anomalies[index]
    original_req = anom.request_data.get("original_request", {})
    mutated_req = anom.request_data
    diff = compute_request_diff(original_req, mutated_req)

    response_summary = {
        "status_code": anom.response_data.get("status_code"),
        "response_time_ms": anom.response_time_ms,
        "matched_keyword": anom.response_data.get("matched_keyword"),
        "matched_text": anom.response_data.get("matched_text"),
        "error": anom.response_data.get("error"),
        "response_body_prefix": anom.response_data.get("response_body_prefix"),
    }

    baseline_info = ""
    base_time = anom.response_data.get("base_time")
    if base_time:
        baseline_info = (
            f"基线响应时间: {base_time:.0f}ms, "
            f"变异响应时间: {anom.response_time_ms:.0f}ms"
        )

    return jsonify({
        "task_id": task_id,
        "index": index,
        "anomaly": {
            "severity": anom.severity,
            "category": anom.category,
            "description": anom.description,
            "trigger_reason": anom.description,
        },
        "request_diff": diff,
        "original_request": original_req,
        "mutated_request": {
            "method": mutated_req.get("method", ""),
            "url": mutated_req.get("url", ""),
            "headers": mutated_req.get("headers", {}),
            "body": mutated_req.get("body", ""),
        },
        "response_summary": response_summary,
        "baseline_comparison": baseline_info,
        "reproduction": {
            "curl": _anomaly_to_curl(anom),
        },
    })


def _anomaly_to_curl(anom) -> str:
    req = anom.request_data
    method = req.get("method", "GET")
    url = req.get("url", "")
    body = req.get("body", "")
    headers = req.get("headers", {})
    cmd = ["curl", "-X", method]
    for k, v in headers.items():
        if k.lower() in ("host", "content-length", "connection"):
            continue
        cmd.extend(["-H", f'{k}: {v}'])
    if body:
        cmd.extend(["-d", body])
    cmd.append(url)
    return " \\\n  ".join(str(x) for x in cmd)


@api.route("/api/fuzz/tasks/<task_id>/save-anomalies", methods=["POST"])
def save_anomalies(task_id):
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404

    body_params = request.get_json(silent=True) or {}

    field_path = body_params.get("field_path") or request.args.get("field_path")
    mutation_type = body_params.get("mutation_type") or request.args.get("mutation_type")
    status_code_min = body_params.get("status_code_min") or request.args.get("status_code_min")
    status_code_max = body_params.get("status_code_max") or request.args.get("status_code_max")

    if status_code_min is not None:
        status_code_min = int(status_code_min)
    if status_code_max is not None:
        status_code_max = int(status_code_max)

    severity_filter = body_params.get("severity")
    if severity_filter and isinstance(severity_filter, str):
        severity_filter = [s.strip() for s in severity_filter.split(",")]

    category_filter = body_params.get("category")
    if category_filter and isinstance(category_filter, str):
        category_filter = [c.strip() for c in category_filter.split(",")]

    format = body_params.get("format", "json")

    filtered = filter_anomalies(
        task.anomalies,
        field_path=field_path,
        mutation_type=mutation_type,
        status_code_min=status_code_min,
        status_code_max=status_code_max,
        severity=severity_filter,
        category=category_filter,
    )
    test_cases = export_anomaly_requests(
        filtered,
        severity_filter=severity_filter,
        category_filter=category_filter,
    )

    applied_filters = {
        "field_path": field_path,
        "mutation_type": mutation_type,
        "status_code_min": status_code_min,
        "status_code_max": status_code_max,
        "severity": severity_filter,
        "category": category_filter,
    }

    if format == "har":
        export_data = format_har_compatible(test_cases)
        return jsonify({
            "task_id": task.task_id,
            "total_anomalies": len(task.anomalies),
            "filtered_count": len(test_cases),
            "applied_filters": applied_filters,
            "format": "har",
            "har_export": export_data,
        })
    elif format == "curl":
        curl_text = format_curl_commands(test_cases)
        return jsonify({
            "task_id": task.task_id,
            "total_anomalies": len(task.anomalies),
            "filtered_count": len(test_cases),
            "applied_filters": applied_filters,
            "format": "curl",
            "curl_text": curl_text,
        })
    elif format == "pytest":
        pytest_text = format_pytest_script(test_cases)
        return jsonify({
            "task_id": task.task_id,
            "total_anomalies": len(task.anomalies),
            "filtered_count": len(test_cases),
            "applied_filters": applied_filters,
            "format": "pytest",
            "pytest_script": pytest_text,
        })
    else:
        har_data = format_har_compatible(test_cases)
        return jsonify({
            "task_id": task.task_id,
            "total_anomalies": len(task.anomalies),
            "filtered_count": len(test_cases),
            "applied_filters": applied_filters,
            "test_cases": test_cases,
            "har_export": har_data,
        })


@api.route("/api/fuzz/tasks", methods=["GET"])
def list_all_tasks():
    return jsonify(list_tasks())


@api.route("/api/fuzz/tasks/<task_id>/cancel", methods=["POST"])
def cancel_task(task_id):
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404

    if task.status in (TaskStatus.RUNNING, TaskStatus.PAUSED):
        task._stopped = True
        task.status = TaskStatus.CANCELLED
        task.progress["phase"] = "cancelled"
        task._pause_event.set()
    else:
        task.status = TaskStatus.CANCELLED
        task.progress["phase"] = "cancelled"

    task.updated_at = time.time()
    storage.save_task(task)
    return jsonify({"task_id": task_id, "status": "cancelled"})