import json
import re
import copy
from urllib.parse import urlencode, urlparse, urlunparse

MAX_INT = 2147483647
MIN_INT = -2147483648

STRING_MUTATIONS = [
    ("empty_string", "", "空字符串"),
    ("null_value", None, "Null值"),
    ("max_length_1k", "A" * 1024, "超长字符串1KB"),
    ("max_length_10k", "A" * 10240, "超长字符串10KB"),
    ("max_length_100k", "A" * 102400, "超长字符串100KB"),
    ("sql_injection_1", "' OR '1'='1", "SQL注入(OR)"),
    ("sql_injection_2", "' OR '1'='1' -- ", "SQL注入(OR注释)"),
    ("sql_injection_3", "1; DROP TABLE users--", "SQL注入(DROP)"),
    ("sql_injection_4", "' UNION SELECT NULL--", "SQL注入(UNION)"),
    ("sql_injection_5", "1' AND SLEEP(5)--", "SQL注入(SLEEP)"),
    ("xss_1", "<script>alert(1)</script>", "XSS注入"),
    ("xss_2", "<img src=x onerror=alert(1)>", "XSS(onerror)"),
    ("xss_3", '"><script>alert(1)</script>', "XSS(属性逃逸)"),
    ("xss_4", "javascript:alert(1)", "XSS(javascript协议)"),
    ("path_traversal_1", "../../../etc/passwd", "路径遍历"),
    ("path_traversal_2", "..\\..\\..\\windows\\system32", "路径遍历(Windows)"),
    ("command_injection_1", "; ls -la", "命令注入(;)"),
    ("command_injection_2", "| cat /etc/passwd", "命令注入(|)"),
    ("command_injection_3", "$(cat /etc/passwd)", "命令注入($())"),
    ("command_injection_4", "`cat /etc/passwd`", "命令注入(``)"),
    ("template_injection_1", "{{7*7}}", "模板注入(SSTI)"),
    ("template_injection_2", "${7*7}", "模板注入(${})"),
    ("unicode_bom", "\ufeff", "BOM字符"),
    ("unicode_rtl", "\u202e", "RTL覆盖"),
    ("unicode_null", "\u0000", "Null字节"),
    ("unicode_homoglyph", "аdmin", "同形字攻击"),
    ("unicode_emoji", "😀💉🔥", "Emoji注入"),
    ("newline_injection", "foo\r\nbar", "换行注入"),
    ("special_chars", "!@#$%^&*()_+-=[]{}|;':\",./<>?", "特殊字符"),
    ("format_string", "%s%s%s%n", "格式化字符串"),
    ("json_nesting", json.dumps({"a": {"b": {"c": {"d": {"e": 1}}}}}), "深层JSON嵌套"),
]

INTEGER_MUTATIONS = [
    ("zero", 0, "零值"),
    ("negative", -1, "负值"),
    ("max_int", MAX_INT, "最大整数"),
    ("min_int", MIN_INT, "最小整数"),
    ("overflow_32", MAX_INT + 1, "32位溢出"),
    ("underflow_32", MIN_INT - 1, "32位下溢"),
    ("overflow_64", 2 ** 64, "64位溢出"),
    ("very_negative", -999999999, "超大负值"),
]

BOOLEAN_MUTATIONS = [
    ("bool_false", False, "False"),
    ("bool_true", True, "True"),
    ("bool_string_true", "true", "字符串true"),
    ("bool_string_false", "false", "字符串false"),
    ("bool_int_1", 1, "整数1"),
    ("bool_int_0", 0, "整数0"),
]

FLOAT_MUTATIONS = [
    ("float_zero", 0.0, "0.0"),
    ("float_negative", -1.5, "负浮点数"),
    ("float_nan_str", "NaN", "NaN字符串"),
    ("float_inf_str", "Infinity", "Infinity字符串"),
    ("float_max", 1.7976931348623157e308, "最大浮点数"),
    ("float_min", 1e-308, "最小正浮点数"),
    ("float_scientific", "1e9999", "科学计数法"),
]

TYPE_CONFUSION_MUTATIONS = [
    ("array_value", ["x"], "数组替代标量"),
    ("object_value", {"key": "value"}, "对象替代标量"),
    ("string_for_number", "not_a_number", "字符串替代数字"),
    ("number_for_bool", 42, "数字替代布尔值"),
]


def get_all_mutations() -> list[tuple[str, object, str]]:
    return (
        STRING_MUTATIONS
        + INTEGER_MUTATIONS
        + BOOLEAN_MUTATIONS
        + FLOAT_MUTATIONS
        + TYPE_CONFUSION_MUTATIONS
    )


def _infer_value_type(value) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        if value.isdigit():
            return "integer"
        try:
            float(value)
            return "float"
        except (ValueError, TypeError):
            pass
        return "string"
    if isinstance(value, (list, tuple)):
        return "array"
    if isinstance(value, dict):
        return "object"
    if value is None:
        return "string"
    return "string"


def _get_mutations_for_type(value) -> list[tuple[str, object, str]]:
    vtype = _infer_value_type(value)
    if vtype in ("integer",):
        return STRING_MUTATIONS + INTEGER_MUTATIONS + TYPE_CONFUSION_MUTATIONS
    if vtype in ("float",):
        return STRING_MUTATIONS + INTEGER_MUTATIONS + FLOAT_MUTATIONS + TYPE_CONFUSION_MUTATIONS
    if vtype == "boolean":
        return STRING_MUTATIONS + BOOLEAN_MUTATIONS + INTEGER_MUTATIONS + TYPE_CONFUSION_MUTATIONS
    if vtype == "array":
        return STRING_MUTATIONS + TYPE_CONFUSION_MUTATIONS
    if vtype == "object":
        return STRING_MUTATIONS + TYPE_CONFUSION_MUTATIONS
    return get_all_mutations()


def extract_fields(body_str: str | None, max_depth: str = "nested") -> dict:
    if not body_str:
        return {}
    try:
        data = json.loads(body_str)
        return _flatten_fields(data, "", max_depth)
    except (json.JSONDecodeError, TypeError):
        form_fields = {}
        for pair in body_str.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                form_fields[k] = v
        return form_fields


def _flatten_fields(data, prefix="", max_depth="nested") -> dict:
    result = {}

    if isinstance(data, dict):
        for k, v in data.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                result[path] = v
                if max_depth == "nested":
                    result.update(_flatten_fields(v, path, max_depth))
            else:
                result[path] = v
    elif isinstance(data, list):
        for i, item in enumerate(data):
            path = f"{prefix}[{i}]"
            if isinstance(item, (dict, list)):
                result[path] = item
                if max_depth == "nested":
                    result.update(_flatten_fields(item, path, max_depth))
            else:
                result[path] = item
    return result


def _is_scalar(value) -> bool:
    return not isinstance(value, (dict, list))


def unflatten_value(fields: dict, path: str, new_value) -> dict:
    parts = re.split(r"\.|(?=\[\d+\])", path)
    parts = [p for p in parts if p]

    def _build(path_parts, value):
        if not path_parts:
            return value
        first = path_parts[0]
        list_match = re.match(r"\[(\d+)\]", first)
        if list_match:
            idx = int(list_match.group(1))
            arr = [None] * (idx + 1)
            arr[idx] = _build(path_parts[1:], value)
            return arr
        rest = _build(path_parts[1:], value)
        return {first: rest}

    return _build(parts, new_value)


def deep_merge(base: dict, overlay: dict) -> dict:
    for k, v in overlay.items():
        if isinstance(v, dict) and k in base and isinstance(base[k], dict):
            deep_merge(base[k], v)
        elif isinstance(v, list) and k in base and isinstance(base[k], list):
            for i, item in enumerate(v):
                if i < len(base[k]) and isinstance(item, dict) and isinstance(base[k][i], dict):
                    deep_merge(base[k][i], item)
                elif i < len(base[k]):
                    base[k][i] = item
                else:
                    base[k].append(item)
        else:
            base[k] = v
    return base


def apply_body_mutation(body_str: str | None, field_path: str, new_value) -> str | None:
    if not body_str:
        return json.dumps({field_path: new_value})
    try:
        root = json.loads(body_str)
    except (json.JSONDecodeError, TypeError):
        if "=" in body_str:
            pairs = body_str.split("&")
            new_pairs = []
            found = False
            for pair in pairs:
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    if k == field_path:
                        new_pairs.append(f"{k}={new_value}")
                        found = True
                    else:
                        new_pairs.append(pair)
            if not found:
                new_pairs.append(f"{field_path}={new_value}")
            return "&".join(new_pairs)
        return body_str

    overlay = unflatten_value({}, field_path, new_value)
    merged = deep_merge(copy.deepcopy(root), overlay)
    return json.dumps(merged)


def apply_url_mutation(url: str, field: str, new_value, location: str = "query") -> str:
    parsed = urlparse(url)

    if location == "path":
        raw_parts = parsed.path.split("/")
        try:
            segment_idx = int(field)
            raw_idx = segment_idx + 1
            if raw_idx < len(raw_parts):
                raw_parts[raw_idx] = str(new_value)
                new_path = "/".join(raw_parts)
                return urlunparse((
                    parsed.scheme, parsed.netloc, new_path,
                    parsed.params, parsed.query, parsed.fragment,
                ))
        except (ValueError, IndexError):
            pass
        return url

    if location == "query":
        params = {}
        if parsed.query:
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
                else:
                    params[pair] = ""
        params[field] = str(new_value)
        new_query = urlencode(params)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))

    return url


def generate_mutations(
    base_request: dict,
    max_depth: str = "top_level",
    enabled_strategies: list[str] | None = None,
    target_locations: list[str] | None = None,
    max_mutations_per_field: int | None = None,
) -> list[dict]:
    if enabled_strategies is None:
        enabled_strategies = ["string", "integer", "special", "unicode", "type_confusion"]
    if target_locations is None:
        target_locations = ["query", "path", "body"]

    mutations = []
    body_fields = extract_fields(base_request.get("body"), max_depth=max_depth)
    query_params = base_request.get("query_params", {})
    path_variables = base_request.get("path_variables", [])
    url = base_request.get("url", "")

    all_fields = []

    if "body" in target_locations:
        for field_name, value in body_fields.items():
            if max_depth == "top_level":
                if "." in field_name or "[" in field_name:
                    continue
                if not _is_scalar(value):
                    continue
            elif max_depth == "nested":
                if not _is_scalar(value):
                    continue
            all_fields.append(("body", field_name, value))

    if "query" in target_locations:
        for field_name, value in query_params.items():
            all_fields.append(("query", field_name, value))

    if "path" in target_locations:
        path_parts = [p for p in urlparse(url).path.split("/") if p]
        for pv in path_variables:
            idx = pv.get("index")
            if idx is not None and idx < len(path_parts):
                segment_name = path_parts[idx]
                all_fields.append(("path", str(idx), pv.get("value", ""), segment_name))

    for field_entry in all_fields:
        if len(field_entry) == 3:
            location, field_name, original_value = field_entry
            segment_name = None
        else:
            location, field_name, original_value, segment_name = field_entry

        display_value = original_value
        if isinstance(display_value, (dict, list)):
            display_value = json.dumps(display_value)

        mutations_for_field = _get_mutations_for_type(original_value)

        field_mutation_count = 0
        for mut_name, mut_value, mut_desc in mutations_for_field:
            strategy = _classify_strategy(mut_name)
            if strategy not in enabled_strategies:
                continue
            if max_mutations_per_field is not None and field_mutation_count >= max_mutations_per_field:
                break

            mutated_req = copy.deepcopy(base_request)

            if location == "body":
                mutated_req["body"] = apply_body_mutation(
                    mutated_req.get("body"), field_name, mut_value,
                )
            elif location == "query":
                mutated_req["url"] = apply_url_mutation(url, field_name, mut_value, "query")
                mutated_req["query_params"] = copy.deepcopy(query_params)
                mutated_req["query_params"][field_name] = str(mut_value)
            elif location == "path":
                mutated_req["url"] = apply_url_mutation(url, field_name, mut_value, "path")

            if location == "path" and segment_name:
                path_label = f"{location}:/.../{segment_name}>seg[{field_name}]"
            else:
                path_label = f"{location}>{field_name}"

            mutations.append({
                "original_request": base_request,
                "mutated_request": mutated_req,
                "mutation_type": mut_name,
                "mutation_desc": mut_desc,
                "field_path": path_label,
                "original_value": str(display_value),
                "mutated_value": str(mut_value),
            })
            field_mutation_count += 1

    return mutations


def _classify_strategy(mutation_name: str) -> str:
    if mutation_name.startswith(("sql_injection", "xss_", "path_traversal",
                                 "command_injection", "template_injection",
                                 "format_string", "special_chars",
                                 "newline_injection")):
        return "special"
    if mutation_name.startswith("unicode_"):
        return "unicode"
    if any(mutation_name.startswith(p) for p in (
        "array_value", "object_value", "string_for_number", "number_for_bool",
    )):
        return "type_confusion"
    if any(mutation_name.startswith(p) for p in ("bool_", "float_")):
        return "integer"
    if mutation_name in ("zero", "negative", "max_int", "min_int",
                          "overflow_32", "underflow_32", "overflow_64",
                          "very_negative"):
        return "integer"
    return "string"