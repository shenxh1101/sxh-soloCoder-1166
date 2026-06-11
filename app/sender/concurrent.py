import time
import json
import concurrent.futures
import requests
from urllib.parse import urlparse


DEFAULT_TIMEOUT = 30
MAX_WORKERS = 20
BASE_HEADERS = {
    "User-Agent": "FuzzTest/1.0",
    "Accept": "*/*",
}


def send_request(
    method: str,
    url: str,
    headers: dict | None = None,
    body: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    merged_headers = {**BASE_HEADERS}
    if headers:
        merged_headers.update(headers)

    try:
        start = time.perf_counter()
        response = requests.request(
            method=method,
            url=url,
            headers=merged_headers,
            data=body,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
        )
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

        try:
            resp_body = response.text[:50000]
        except Exception:
            resp_body = "<binary or encoding error>"

        return {
            "status_code": response.status_code,
            "response_time_ms": elapsed_ms,
            "response_body": resp_body,
            "response_headers": dict(response.headers),
            "error": None,
        }
    except requests.exceptions.Timeout:
        return {
            "status_code": None,
            "response_time_ms": timeout * 1000,
            "response_body": None,
            "response_headers": {},
            "error": "timeout",
        }
    except requests.exceptions.ConnectionError as e:
        return {
            "status_code": None,
            "response_time_ms": 0,
            "response_body": None,
            "response_headers": {},
            "error": f"connection_error: {str(e)[:200]}",
        }
    except Exception as e:
        return {
            "status_code": None,
            "response_time_ms": 0,
            "response_body": None,
            "response_headers": {},
            "error": f"error: {str(e)[:200]}",
        }


def send_batch(
    mutations: list[dict],
    concurrency: int = 10,
    timeout: int = DEFAULT_TIMEOUT,
    progress_callback=None,
) -> list[dict]:
    concurrency = min(concurrency, MAX_WORKERS)
    results = []
    total = len(mutations)

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_mutation = {}
        for i, mutation in enumerate(mutations):
            req = mutation["mutated_request"]
            future = executor.submit(
                send_request,
                method=req.get("method", "GET"),
                url=req["url"],
                headers=req.get("headers"),
                body=req.get("body"),
                timeout=timeout,
            )
            future_to_mutation[future] = (i, mutation)

        for future in concurrent.futures.as_completed(future_to_mutation):
            idx, mutation = future_to_mutation[future]
            resp = future.result()
            result = {**mutation, **resp}
            results.append(result)

            if progress_callback:
                progress_callback(idx + 1, total)

    return results