import json
import os
import time
from dataclasses import asdict
from app.models import FuzzTask, Anomaly, TaskStatus, Severity

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
TASKS_DIR = os.path.join(DATA_DIR, "tasks")


def _ensure_dirs():
    os.makedirs(TASKS_DIR, exist_ok=True)


def _anomaly_to_storable(a: Anomaly) -> dict:
    d = asdict(a)
    d["severity"] = a.severity.value
    return d


def _anomaly_from_storable(d: dict) -> Anomaly:
    severity = Severity(d["severity"])
    return Anomaly(
        severity=severity,
        category=d["category"],
        description=d["description"],
        request_data=d["request_data"],
        response_data=d["response_data"],
        response_time_ms=d["response_time_ms"],
    )


def _task_to_storable(task: FuzzTask) -> dict:
    return {
        "task_id": task.task_id,
        "status": task.status.value,
        "config": task.config,
        "base_requests": task.base_requests,
        "all_mutations": task.all_mutations,
        "sent_count": task.sent_count,
        "results": task.results,
        "anomalies": [_anomaly_to_storable(a) for a in task.anomalies],
        "progress": task.progress,
        "report": task.report,
        "created_at": task.created_at,
        "updated_at": time.time(),
        "baseline": getattr(task, "baseline", None),
        "dedup_skipped": getattr(task, "dedup_skipped", 0),
    }


def _task_from_storable(d: dict) -> FuzzTask:
    anomalies = [_anomaly_from_storable(a) for a in d.get("anomalies", [])]
    task = FuzzTask(
        task_id=d["task_id"],
        config=d.get("config", {}),
        base_requests=d.get("base_requests", []),
        all_mutations=d.get("all_mutations", []),
        sent_count=d.get("sent_count", 0),
        results=d.get("results", []),
        anomalies=anomalies,
        progress=d.get("progress", {}),
        report=d.get("report", {}),
        created_at=d.get("created_at", time.time()),
        updated_at=d.get("updated_at", time.time()),
    )
    task.status = TaskStatus(d.get("status", "pending"))
    task.baseline = d.get("baseline")
    task.dedup_skipped = d.get("dedup_skipped", 0)
    return task


def save_task(task: FuzzTask):
    _ensure_dirs()
    data = _task_to_storable(task)
    path = os.path.join(TASKS_DIR, f"{task.task_id}.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, default=str)
    os.replace(tmp, path)


def load_all_tasks() -> list[FuzzTask]:
    _ensure_dirs()
    tasks = []
    if not os.path.isdir(TASKS_DIR):
        return tasks
    for filename in sorted(os.listdir(TASKS_DIR)):
        if not filename.endswith(".json"):
            continue
        path = os.path.join(TASKS_DIR, filename)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            task = _task_from_storable(data)
            tasks.append(task)
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return tasks


def restore_tasks_into(target_dict: dict[str, FuzzTask]):
    tasks = load_all_tasks()
    for task in tasks:
        target_dict[task.task_id] = task
    return len(tasks)