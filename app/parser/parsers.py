import json
from urllib.parse import urlparse, parse_qs, unquote
from app.models import BaseRequest


def parse_har(har_content: str | bytes) -> list[BaseRequest]:
    if isinstance(har_content, bytes):
        har_content = har_content.decode("utf-8")
    har_data = json.loads(har_content)
    entries = har_data["log"]["entries"]
    return [_parse_har_entry(e) for e in entries]


def _parse_har_entry(entry: dict) -> BaseRequest:
    request = entry["request"]
    method = request["method"]
    url = request["url"]
    parsed_url = urlparse(url)

    headers = {}
    for h in request.get("headers", []):
        headers[h["name"]] = h["value"]

    query_params = {}
    if parsed_url.query:
        query_params = {
            k: v[0] if len(v) == 1 else v
            for k, v in parse_qs(parsed_url.query, keep_blank_values=True).items()
        }

    body = None
    if request.get("postData"):
        body = request["postData"].get("text", "")

    path_parts = [p for p in parsed_url.path.split("/") if p]
    path_variables = _extract_path_variables(path_parts)

    return BaseRequest(
        method=method,
        url=url,
        headers=headers,
        body=body,
        query_params=query_params,
        path_variables=path_variables,
    )


def _extract_path_variables(path_parts: list[str]) -> list[dict]:
    variables = []
    for i, part in enumerate(path_parts):
        if part.isdigit():
            variables.append({"index": i, "value": part, "type": "integer"})
        elif any(c in part for c in "-_."):
            variables.append({"index": i, "value": part, "type": "string"})
        else:
            variables.append({"index": i, "value": part, "type": "string"})
    return variables


def parse_curl(curl_commands: str) -> list[BaseRequest]:
    lines = curl_commands.strip().split("\n")
    requests = []
    current = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("curl ") and current:
            requests.append(_parse_single_curl("\n".join(current)))
            current = [stripped]
        else:
            current.append(stripped)
    if current:
        requests.append(_parse_single_curl("\n".join(current)))
    return requests


def _parse_single_curl(command: str) -> BaseRequest:
    import shlex

    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.replace("\\\n", " ").split()

    method = "GET"
    url = ""
    headers = {}
    data = None
    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token == "-X" or token == "--request":
            i += 1
            method = tokens[i].upper()
        elif token.startswith("-X"):
            method = token[2:].upper() or tokens[i + 1].upper()
            if not method:
                i += 1
                method = tokens[i].upper()
        elif token == "-H" or token == "--header":
            i += 1
            header_str = tokens[i]
            if ": " in header_str:
                key, val = header_str.split(": ", 1)
                headers[key] = val
        elif token.startswith("-H"):
            header_str = token[2:] if token[2] != " " else token[3:]
            if ": " in header_str:
                key, val = header_str.split(": ", 1)
                headers[key] = val
        elif token == "-d" or token == "--data" or token == "--data-raw":
            i += 1
            data = tokens[i]
        elif token.startswith("-d") or token.startswith("--data"):
            data = token.split(" ", 1)[1] if " " in token else tokens[i + 1]
            if " " in token:
                pass
            else:
                i += 1
        elif not token.startswith("-") and not url:
            url = token
        i += 1

    if not url and len(tokens) > 1:
        for t in tokens[1:]:
            if not t.startswith("-"):
                url = t
                break

    parsed_url = urlparse(url)
    query_params = {}
    if parsed_url.query:
        query_params = {
            k: v[0] if len(v) == 1 else v
            for k, v in parse_qs(parsed_url.query, keep_blank_values=True).items()
        }

    path_parts = [p for p in parsed_url.path.split("/") if p]
    path_variables = _extract_path_variables(path_parts)

    return BaseRequest(
        method=method,
        url=url,
        headers=headers,
        body=data,
        query_params=query_params,
        path_variables=path_variables,
    )