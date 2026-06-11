import uuid
import time
import threading
from enum import Enum
from dataclasses import dataclass, field


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class BaseRequest:
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: str | None = None
    query_params: dict = field(default_factory=dict)
    path_variables: list = field(default_factory=list)


@dataclass
class MutationResult:
    original_request: dict
    mutated_request: dict
    mutation_type: str
    field_path: str
    mutated_value: str
    status_code: int | None = None
    response_time_ms: float | None = None
    response_body: str | None = None
    response_headers: dict = field(default_factory=dict)
    error: str | None = None
    anomalies: list = field(default_factory=list)


@dataclass
class Anomaly:
    severity: Severity
    category: str
    description: str
    request_data: dict
    response_data: dict
    response_time_ms: float


@dataclass
class FuzzTask:
    task_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    status: TaskStatus = TaskStatus.PENDING
    config: dict = field(default_factory=dict)
    base_requests: list = field(default_factory=list)
    all_mutations: list = field(default_factory=list)
    sent_count: int = 0
    results: list = field(default_factory=list)
    anomalies: list = field(default_factory=list)
    progress: dict = field(default_factory=dict)
    report: dict = field(default_factory=dict)
    baseline: dict | None = None
    dedup_skipped: int = 0
    run_generation: int = 1
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    _thread: threading.Thread | None = field(default=None, repr=False)
    _pause_event: threading.Event = field(default_factory=threading.Event, repr=False)
    _stopped: bool = field(default=False, repr=False)


_tasks: dict[str, FuzzTask] = {}


def _init_storage():
    from app.storage import restore_tasks_into

    count = restore_tasks_into(_tasks)
    if count > 0:
        print(f"[storage] 从磁盘恢复了 {count} 个历史任务")


_init_storage()


def create_task(config: dict, base_requests: list) -> FuzzTask:
    task = FuzzTask(config=config, base_requests=base_requests)
    _tasks[task.task_id] = task
    return task


def get_task(task_id: str) -> FuzzTask | None:
    return _tasks.get(task_id)


def list_tasks() -> list:
    return [
        {
            "task_id": t.task_id,
            "status": t.status.value,
            "progress": t.progress,
            "created_at": t.created_at,
            "anomaly_count": len(t.anomalies),
        }
        for t in _tasks.values()
    ]