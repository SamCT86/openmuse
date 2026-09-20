"""Standards-based JSON Schema validation for tool action boundaries."""

from collections.abc import Mapping
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError


class SchemaValidationError(ValueError):
    pass


def validate_arguments(arguments: Mapping[str, Any], schema: Mapping[str, Any] | None) -> None:
    """Validate tool arguments against JSON Schema Draft 2020-12."""
    if schema is None:
        return
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(dict(arguments))
    except (SchemaError, ValidationError) as error:
        raise SchemaValidationError(error.message) from error
