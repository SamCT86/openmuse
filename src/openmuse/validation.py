"""Small, dependency-free JSON Schema subset for tool action boundaries."""

from collections.abc import Mapping
from typing import Any


class SchemaValidationError(ValueError):
    pass


def validate_arguments(arguments: Mapping[str, Any], schema: Mapping[str, Any] | None) -> None:
    """Validate the object/required/properties subset emitted by OpenMuse tools.

    The runtime fails closed for unsupported schema keywords instead of silently
    claiming validation it does not perform.
    """
    if schema is None:
        return
    supported = {"type", "required", "properties", "additionalProperties"}
    unknown = set(schema) - supported
    if unknown:
        raise SchemaValidationError(f"unsupported schema keywords: {', '.join(sorted(unknown))}")
    if schema.get("type", "object") != "object":
        raise SchemaValidationError("tool schema root must be an object")

    properties = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(properties, Mapping) or not isinstance(required, list):
        raise SchemaValidationError("invalid object schema")
    missing = [name for name in required if name not in arguments]
    if missing:
        raise SchemaValidationError(f"missing required argument: {missing[0]}")
    if schema.get("additionalProperties") is False:
        extra = set(arguments) - set(properties)
        if extra:
            raise SchemaValidationError(f"unexpected argument: {min(extra)}")

    type_map: dict[str, type[Any] | tuple[type[Any], ...]] = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "object": Mapping,
        "array": list,
        "null": type(None),
    }
    for name, value in arguments.items():
        property_schema = properties.get(name)
        if property_schema is None:
            continue
        if not isinstance(property_schema, Mapping) or set(property_schema) - {"type"}:
            raise SchemaValidationError(f"unsupported schema for argument: {name}")
        expected = property_schema.get("type")
        if expected not in type_map:
            raise SchemaValidationError(f"unsupported type for argument {name}: {expected}")
        if expected in {"integer", "number"} and isinstance(value, bool):
            raise SchemaValidationError(f"argument {name} must be {expected}")
        if not isinstance(value, type_map[expected]):
            raise SchemaValidationError(f"argument {name} must be {expected}")
