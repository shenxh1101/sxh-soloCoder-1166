import json
import time
import copy
from flask import Blueprint, request, jsonify

from app.models import (
    TaskStatus,
    create_task,
    get_task,
    list_tasks,
)
from app.parser.parsers import parse_har, parse_curl
from app.mutator.engine import generate_mutations
from app.sender.concurrent import send_batch
from app.analyzer.detector import analyze_response
from dataclasses import asdict

from app.reporter.generator import (
    generate_report,
    export_anomaly_requests,
    format_har_compatible,
)

api = Blueprint("api", __name__)


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
    }

    task = create_task(config, samples)

    return jsonify({"task_id": task.task_id, "status": task.status.value})


@api.route("/api/fuzz/run/<task_id>", methods=["POST"])
def run_fuzz(task_id):
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404
    if task.status == TaskStatus.RUNNING:
        return jsonify({"error": "任务已在运行中"}), 409

    task.status = TaskStatus.RUNNING
    task.updated_at = time.time()

    results = []
    anomalies = []
    all_mutations = []
    base_requests = task.base_requests

    for br in base_requests:
        muts = generate_mutations(
            br,
            max_depth=task.config.get("max_depth", "top_level"),
            enabled_strategies=task.config.get("enabled_strategies"),
        )
        all_mutations.extend(muts)

    task.progress = {
        "total_mutations": len(all_mutations),
        "sent": 0,
        "anomalies_found": 0,
    }

    batch_size = task.config.get("concurrency", 10)

    for i in range(0, len(all_mutations), batch_size):
        if task.status == TaskStatus.CANCELLED:
            break

        batch = all_mutations[i : i + batch_size]
        batch_results = send_batch(
            batch,
            concurrency=task.config.get("concurrency", 10),
            timeout=task.config.get("timeout", 30),
        )
        results.extend(batch_results)

        for br_result in batch_results:
            br_result_anomalies = analyze_response(
                br_result,
                blacklist=task.config.get("blacklist"),
                slow_threshold_ms=task.config.get("slow_threshold_ms", 5000),
            )
            anomalies.extend(br_result_anomalies)

        task.progress["sent"] = i + len(batch)
        task.progress["anomalies_found"] = len(anomalies)
        task.updated_at = time.time()

    task.results = results
    task.anomalies = anomalies

    report = generate_report(
        task_id=task.task_id,
        base_requests=base_requests,
        results=results,
        anomalies=anomalies,
        config=task.config,
        start_time=task.created_at,
        end_time=time.time(),
    )
    task.report = report
    task.status = TaskStatus.COMPLETED
    task.progress = {
        "total_mutations": len(all_mutations),
        "sent": len(results),
        "anomalies_found": len(anomalies),
    }
    task.updated_at = time.time()

    return jsonify({"task_id": task_id, "status": "completed"})


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
            "message": "任务尚未完成，暂无报告",
        })

    return jsonify(task.report)


@api.route("/api/fuzz/tasks/<task_id>/anomalies", methods=["GET"])
def task_anomalies(task_id):
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404

    return jsonify({
        "task_id": task.task_id,
        "count": len(task.anomalies),
        "anomalies": [asdict(a) for a in task.anomalies],
    })


@api.route("/api/fuzz/tasks/<task_id>/save-anomalies", methods=["POST"])
def save_anomalies(task_id):
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404

    test_cases = export_anomaly_requests(task.anomalies)
    har_data = format_har_compatible(test_cases)

    return jsonify({
        "task_id": task.task_id,
        "test_case_count": len(test_cases),
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

    task.status = TaskStatus.CANCELLED
    task.updated_at = time.time()
    return jsonify({"task_id": task_id, "status": "cancelled"})