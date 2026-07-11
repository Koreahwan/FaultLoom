"""Stdlib-only JSON-lines worker used by the reference SDK process."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime
from typing import NoReturn

MAX_RPC_BYTES = 1_048_576
MAX_SCHEMA_BYTES = 131_072
SCHEMA_VERSION = "0.1.0"
RPC_VERSION = "0.1.0"
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
WIRE_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?"
    r"(?:[Zz]|[+-](?P<offset_hour>\d{2}):(?P<offset_minute>\d{2}))$"
)

INPUT_SCHEMA_DIGEST = "sha256:6a084ecbce279e360616dbc5a945e42ea8c88163a84bc40551877a96975db02a"
OUTPUT_SCHEMA_DIGEST = "sha256:c9397046a37dc06721f0f2010a88c0761636a05e5a98dccbad33b5ad8d75a64d"


def _deny_network(event: str, _arguments: tuple[object, ...]) -> None:
    if event.startswith("socket."):
        raise PermissionError("network disabled in reference worker")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(value: object) -> str:
    data = value if isinstance(value, bytes) else _canonical(value)
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _identifier(value: object) -> bool:
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def _canonical_wire_string(
    value: object, *, format_name: object = None
) -> str | None:
    if not isinstance(value, str):
        return None
    if format_name is None:
        return value if value.strip() else None
    if format_name != "date-time":
        return None
    match = WIRE_DATETIME.fullmatch(value)
    if match is None:
        return None
    offset_hour = match.group("offset_hour")
    offset_minute = match.group("offset_minute")
    if offset_hour is not None and (
        int(offset_hour) > 23 or int(offset_minute) > 59
    ):
        return None
    normalized = value[:-1] + "+00:00" if value[-1] in "Zz" else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return value


def _aware_datetime(value: object) -> bool:
    return _canonical_wire_string(value, format_name="date-time") is not None


def _json_equal(left: object, right: object) -> bool:
    try:
        return _canonical(left) == _canonical(right)
    except (TypeError, ValueError):
        return False


def _json_type_matches(value: object, expected: str) -> bool:
    return {
        "array": isinstance(value, list),
        "boolean": type(value) is bool,
        "integer": type(value) is int,
        "null": value is None,
        "number": type(value) in {int, float},
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
    }.get(expected, False)


def _schema_valid(value: object, schema: object, root: dict[str, object]) -> bool:
    if not isinstance(schema, dict):
        return False
    reference = schema.get("$ref")
    if reference is not None:
        if not isinstance(reference, str) or not reference.startswith("#/$defs/"):
            return False
        name = reference.removeprefix("#/$defs/")
        definitions = root.get("$defs")
        if not isinstance(definitions, dict) or name not in definitions:
            return False
        if not _schema_valid(value, definitions[name], root):
            return False
    one_of = schema.get("oneOf")
    if one_of is not None:
        if not isinstance(one_of, list):
            return False
        if sum(_schema_valid(value, choice, root) for choice in one_of) != 1:
            return False
    any_of = schema.get("anyOf")
    if any_of is not None:
        if not isinstance(any_of, list):
            return False
        if not any(_schema_valid(value, choice, root) for choice in any_of):
            return False
    if "const" in schema and not _json_equal(value, schema["const"]):
        return False
    choices = schema.get("enum")
    if choices is not None:
        if not isinstance(choices, list) or not any(
            _json_equal(value, choice) for choice in choices
        ):
            return False
    expected_type = schema.get("type")
    if expected_type is not None:
        if not isinstance(expected_type, str) or not _json_type_matches(
            value, expected_type
        ):
            return False
    if isinstance(value, str):
        wire_value = _canonical_wire_string(value, format_name=schema.get("format"))
        if wire_value is None:
            return False
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if minimum is not None and (
            type(minimum) is not int or len(wire_value) < minimum
        ):
            return False
        if maximum is not None and (
            type(maximum) is not int or len(wire_value) > maximum
        ):
            return False
        pattern = schema.get("pattern")
        if pattern is not None:
            if not isinstance(pattern, str):
                return False
            try:
                if re.search(pattern, wire_value) is None:
                    return False
            except re.error:
                return False
    if type(value) is int:
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and (type(minimum) is not int or value < minimum):
            return False
        if maximum is not None and (type(maximum) is not int or value > maximum):
            return False
    if isinstance(value, list):
        items = schema.get("items")
        if items is not None and not all(
            _schema_valid(item, items, root) for item in value
        ):
            return False
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            return False
        if not all(isinstance(name, str) and name in value for name in required):
            return False
        for name, child in value.items():
            child_schema = properties.get(name)
            if child_schema is not None:
                if not _schema_valid(child, child_schema, root):
                    return False
            elif schema.get("additionalProperties") is False:
                return False
            elif isinstance(schema.get("additionalProperties"), dict):
                if not _schema_valid(child, schema["additionalProperties"], root):
                    return False
    return True


def _load_input_schema(raw: str) -> dict[str, object] | None:
    encoded = raw.encode("utf-8")
    if not encoded or len(encoded) > MAX_SCHEMA_BYTES:
        return None
    try:
        schema = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(schema, dict) or _canonical(schema) != encoded:
        return None
    if _digest(schema) != INPUT_SCHEMA_DIGEST:
        return None
    return schema


def _exact_mapping(value: object, fields: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == fields


def _valid_subject(value: object) -> bool:
    fields = {"schema_version", "subject_id", "subject_kind", "identity_id", "tenant_id"}
    return (
        _exact_mapping(value, fields)
        and value["schema_version"] == SCHEMA_VERSION
        and _identifier(value["subject_id"])
        and _identifier(value["subject_kind"])
        and (value["identity_id"] is None or _identifier(value["identity_id"]))
        and (value["tenant_id"] is None or _identifier(value["tenant_id"]))
    )


def _valid_resource(value: object) -> bool:
    fields = {"schema_version", "resource_id", "resource_kind", "target_id", "tenant_id"}
    return (
        _exact_mapping(value, fields)
        and value["schema_version"] == SCHEMA_VERSION
        and _identifier(value["resource_id"])
        and _identifier(value["resource_kind"])
        and _identifier(value["target_id"])
        and (value["tenant_id"] is None or _identifier(value["tenant_id"]))
    )


def _valid_state(value: object) -> bool:
    if value is None:
        return True
    fields = {"schema_version", "state_id", "state_kind", "state_version", "state_digest"}
    return (
        _exact_mapping(value, fields)
        and value["schema_version"] == SCHEMA_VERSION
        and _identifier(value["state_id"])
        and _identifier(value["state_kind"])
        and type(value["state_version"]) is int
        and 0 <= value["state_version"] <= 2**63 - 1
        and (value["state_digest"] is None or _valid_digest(value["state_digest"]))
    )


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def _valid_intent(value: object) -> bool:
    fields = {
        "schema_version",
        "action_id",
        "run_id",
        "target_id",
        "pack_id",
        "action_kind",
        "action_class",
        "subject",
        "resource",
        "state",
        "protocol",
        "method",
        "path",
        "payload_digest",
        "requested_at",
        "parent_action_ids",
        "canary_ref",
        "cleanup_plan_ref",
    }
    if not _exact_mapping(value, fields):
        return False
    identifiers = ("action_id", "run_id", "target_id", "pack_id", "action_kind")
    return (
        value["schema_version"] == SCHEMA_VERSION
        and all(_identifier(value[field]) for field in identifiers)
        and value["pack_id"] == "pack.reference"
        and value["action_kind"] == "reference.digest"
        and value["action_class"] in {"observe", "safe_probe"}
        and _valid_subject(value["subject"])
        and _valid_resource(value["resource"])
        and value["resource"]["target_id"] == value["target_id"]
        and _valid_state(value["state"])
        and isinstance(value["protocol"], str)
        and (value["method"] is None or isinstance(value["method"], str))
        and (value["path"] is None or isinstance(value["path"], str))
        and (value["payload_digest"] is None or _valid_digest(value["payload_digest"]))
        and _aware_datetime(value["requested_at"])
        and isinstance(value["parent_action_ids"], list)
        and all(_identifier(item) for item in value["parent_action_ids"])
        and (value["canary_ref"] is None or _identifier(value["canary_ref"]))
        and (value["cleanup_plan_ref"] is None or _identifier(value["cleanup_plan_ref"]))
    )


def _valid_observation(value: object) -> bool:
    fields = {
        "schema_version",
        "observation_id",
        "run_id",
        "cas_digest",
        "media_type",
        "byte_length",
        "cursor",
        "created_at",
    }
    return (
        _exact_mapping(value, fields)
        and value["schema_version"] == SCHEMA_VERSION
        and _identifier(value["observation_id"])
        and _identifier(value["run_id"])
        and _valid_digest(value["cas_digest"])
        and isinstance(value["media_type"], str)
        and type(value["byte_length"]) is int
        and 0 <= value["byte_length"] <= 2**63 - 1
        and (value["cursor"] is None or _identifier(value["cursor"]))
        and _aware_datetime(value["created_at"])
    )


def _base_response(request_id: str) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "rpc_version": RPC_VERSION,
        "request_id": request_id,
    }


def _error(request_id: object, code: str, message: str) -> dict[str, object]:
    safe_id = request_id if _identifier(request_id) else "invalid.request"
    return {
        **_base_response(safe_id),
        "status": "error",
        "error_code": code,
        "error_message": message,
    }


def _network_guard_active() -> bool:
    return True


def _manifests(worker_digest: str) -> tuple[dict[str, object], dict[str, object]]:
    pack = {
        "schema_version": SCHEMA_VERSION,
        "pack_id": "pack.reference",
        "pack_version": "0.1.0",
        "protocol_range": ">=0.1.0,<0.2.0",
        "schema_namespace": "faultloom.reference.v1",
        "capability_descriptors": ["reference.local_transform"],
        "action_compilers": ["reference.digest"],
        "observation_normalizers": ["reference.observation_digest"],
        "hypothesis_providers": ["reference.hypothesis"],
        "verifier_descriptors": ["reference.verifier"],
        "evaluation_descriptors": ["reference.evaluation"],
        "required_gateway_features": ["dispatch.leases"],
        "required_adapter_capabilities": ["reference.digest_normalizer"],
        "process_isolation": "required",
    }
    adapter = {
        "schema_version": SCHEMA_VERSION,
        "adapter_id": "adapter.reference",
        "adapter_version": "0.1.0",
        "upstream_version": "0.1.0",
        "upstream_commit": None,
        "image_digest": worker_digest,
        "license_class": "bundled_open_source",
        "capabilities": ["reference.digest_normalizer"],
        "action_classes": ["observe", "safe_probe"],
        "network_mode": "none",
        "input_schema_digest": INPUT_SCHEMA_DIGEST,
        "output_schema_digest": OUTPUT_SCHEMA_DIGEST,
        "budget": {
            "schema_version": SCHEMA_VERSION,
            "rate_per_minute": 60,
            "timeout_seconds": 5,
            "max_bytes": MAX_RPC_BYTES,
            "max_concurrency": 1,
        },
        "telemetry_policy": "disabled",
        "update_policy": "pinned_no_runtime_updates",
        "evidence_capability": "candidate_only",
    }
    return pack, adapter


def _handle(
    document: object,
    *,
    worker_digest: str,
    input_schema: dict[str, object],
) -> dict[str, object]:
    if not isinstance(document, dict):
        return _error(None, "rpc.invalid_request", "request must be one object")
    request_id = document.get("request_id")
    method = document.get("method")
    common = (
        document.get("schema_version") == SCHEMA_VERSION
        and document.get("rpc_version") == RPC_VERSION
        and _identifier(request_id)
    )
    if not common:
        return _error(request_id, "rpc.invalid_request", "invalid RPC envelope")
    if method not in {"describe", "compile_action", "normalize_observation"}:
        return _error(request_id, "rpc.unknown_method", "method is not admitted")
    if not _schema_valid(document, input_schema, input_schema):
        return _error(request_id, "rpc.invalid_request", "request violates RPC schema")
    if method == "describe":
        fields = {"schema_version", "rpc_version", "request_id", "method"}
        if set(document) != fields:
            return _error(request_id, "rpc.invalid_request", "unexpected describe fields")
        if not _network_guard_active():
            return _error(request_id, "sandbox.network_guard", "network guard unavailable")
        pack, adapter = _manifests(worker_digest)
        return {
            **_base_response(request_id),
            "status": "ok",
            "pack_manifest": pack,
            "adapter_manifest": adapter,
            "network_guard_active": True,
        }
    if method == "compile_action":
        fields = {
            "schema_version",
            "rpc_version",
            "request_id",
            "method",
            "authority_grant_digest",
            "action_intent",
        }
        if (
            set(document) != fields
            or not _valid_digest(document.get("authority_grant_digest"))
            or not _valid_intent(document.get("action_intent"))
        ):
            return _error(request_id, "rpc.invalid_request", "invalid compile request")
        intent = document["action_intent"]
        return {
            **_base_response(request_id),
            "status": "ok",
            "compiled_action": {
                "schema_version": SCHEMA_VERSION,
                "action_id": intent["action_id"],
                "pack_id": intent["pack_id"],
                "compiler_id": intent["action_kind"],
                "intent_digest": _digest(intent),
                "required_network_mode": "gateway_only",
                "dispatch_authorized": False,
            },
        }
    if method == "normalize_observation":
        fields = {
            "schema_version",
            "rpc_version",
            "request_id",
            "method",
            "authority_grant_digest",
            "adapter_id",
            "capability",
            "observation",
        }
        if (
            set(document) != fields
            or not _valid_digest(document.get("authority_grant_digest"))
            or document.get("adapter_id") != "adapter.reference"
            or document.get("capability") != "reference.digest_normalizer"
            or not _valid_observation(document.get("observation"))
        ):
            return _error(request_id, "rpc.invalid_request", "invalid normalize request")
        observation = document["observation"]
        return {
            **_base_response(request_id),
            "status": "ok",
            "normalized_observation": {
                "schema_version": SCHEMA_VERSION,
                "adapter_id": document["adapter_id"],
                "normalizer_id": document["capability"],
                "observation_id": observation["observation_id"],
                "source_digest": observation["cas_digest"],
            },
        }
    return _error(request_id, "rpc.unknown_method", "method is not admitted")


def _write(document: dict[str, object]) -> NoReturn:
    sys.stdout.buffer.write(_canonical(document) + b"\n")
    sys.stdout.buffer.flush()
    raise SystemExit(0)


def main() -> NoReturn:
    sys.addaudithook(_deny_network)
    if len(sys.argv) != 3 or not _valid_digest(sys.argv[1]):
        _write(_error(None, "rpc.invalid_worker_digest", "worker digest is not bound"))
    worker_digest = sys.argv[1]
    input_schema = _load_input_schema(sys.argv[2])
    if input_schema is None:
        _write(_error(None, "rpc.invalid_schema", "input schema is not bound"))
    raw = sys.stdin.buffer.readline(MAX_RPC_BYTES + 1)
    if not raw or len(raw) > MAX_RPC_BYTES or not raw.endswith(b"\n"):
        _write(_error(None, "rpc.invalid_size", "request must be one bounded JSON line"))
    if sys.stdin.buffer.read(1):
        _write(_error(None, "rpc.invalid_size", "only one request is accepted"))
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _write(_error(None, "rpc.invalid_json", "request is not valid JSON"))
    _write(_handle(document, worker_digest=worker_digest, input_schema=input_schema))


if __name__ == "__main__":
    main()
