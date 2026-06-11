import uuid
import time
from enum import Enum
from dataclasses import dataclass, field, asdict


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
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
    results: list = field(default_factory=list)
    anomalies: list = field(default_factory=list)
    progress: dict = field(default_factory=dict)
    report: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


_tasks: dict[str, FuzzTask] = {}


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