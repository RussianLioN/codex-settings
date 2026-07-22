"""Закрытый исполнитель нормативного подмножества JSON Schema 2020-12.

Модуль не пытается быть общей реализацией JSON Schema. Он принимает только
явно перечисленные ключи, форматы и ссылки на соседние схемы одного каталога.
Расширение нормативного словаря требует сначала расширить этот исполнитель и
его сравнительные проверки.
"""

from __future__ import annotations

import calendar
import json
import math
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urldefrag, urljoin, urlsplit


ClosedValidatorV2 = Callable[[Any], None]
_DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
_MAX_SCHEMA_BYTES = 4 * 1024 * 1024
_MAX_VALIDATION_DEPTH = 512
_SCHEMA_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.json$")
_RFC3339 = re.compile(
    r"^(\d{4})-(0[1-9]|1[0-2])-(\d{2})"
    r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?"
    r"(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)
_TYPE_NAMES = frozenset(
    {"array", "boolean", "integer", "null", "number", "object", "string"}
)
_SUPPORTED_KEYWORDS = frozenset(
    {
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "additionalProperties",
        "allOf",
        "const",
        "contains",
        "description",
        "else",
        "enum",
        "format",
        "if",
        "items",
        "maxContains",
        "maxItems",
        "maxLength",
        "maxProperties",
        "maximum",
        "minContains",
        "minItems",
        "minLength",
        "minProperties",
        "minimum",
        "not",
        "oneOf",
        "pattern",
        "prefixItems",
        "properties",
        "required",
        "then",
        "title",
        "type",
        "uniqueItems",
    }
)


class ClosedJsonSchemaV2Error(ValueError):
    """Схема либо значение вышли за закрытый договор исполнителя."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: Sequence[str | int] = (),
    ) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.path = tuple(path)


@dataclass(frozen=True)
class _ResourceV2:
    name: str
    identity: str
    schema: Mapping[str, Any]


class _RegistryV2:
    def __init__(self, schema_directory: Path) -> None:
        self.schema_directory = schema_directory
        self.by_name: dict[str, _ResourceV2] = {}
        self.by_identity: dict[str, _ResourceV2] = {}
        self.preparing: set[str] = set()
        self.prepared: set[str] = set()

    def load(self, name: str) -> _ResourceV2:
        if name in self.by_name:
            return self.by_name[name]
        if _SCHEMA_NAME.fullmatch(name) is None or Path(name).name != name:
            _definition(
                "SCHEMA_NAME_INVALID",
                f"небезопасное имя схемы: {name}",
            )
        path = self.schema_directory / name
        try:
            information = path.lstat()
            if (
                not stat.S_ISREG(information.st_mode)
                or stat.S_ISLNK(information.st_mode)
                or information.st_size > _MAX_SCHEMA_BYTES
            ):
                _definition(
                    "SCHEMA_FILE_INVALID",
                    f"схема не является ограниченным обычным файлом: {name}",
                )
            payload = path.read_bytes()
        except OSError as error:
            _definition(
                "SCHEMA_REFERENCE_UNRESOLVED",
                f"нет схемы {name}: {error}",
            )
        try:
            document = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=lambda value: (_raise_json_constant(value)),
            )
        except (UnicodeError, json.JSONDecodeError) as error:
            _definition(
                "SCHEMA_JSON_INVALID",
                f"неверный JSON в {name}: {error}",
            )
        if type(document) is not dict:
            _definition(
                "SCHEMA_ROOT_INVALID",
                f"корень {name} не является объектом",
            )
        if document.get("$schema") != _DRAFT_2020_12:
            _definition(
                "SCHEMA_DIALECT_UNSUPPORTED",
                f"{name} не объявляет Draft 2020-12",
            )
        identity = document.get("$id")
        if type(identity) is not str:
            _definition(
                "SCHEMA_ID_INVALID",
                f"{name} не содержит строковый $id",
            )
        parsed = urlsplit(identity)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.query
            or parsed.fragment
            or Path(parsed.path).name != name
        ):
            _definition("SCHEMA_ID_INVALID", f"неверный $id схемы {name}")
        if identity in self.by_identity:
            _definition("SCHEMA_ID_DUPLICATE", f"повтор $id схемы {name}")
        resource = _ResourceV2(name=name, identity=identity, schema=document)
        self.by_name[name] = resource
        self.by_identity[identity] = resource
        return resource

    def prepare(self, resource: _ResourceV2) -> None:
        if resource.name in self.prepared or resource.name in self.preparing:
            return
        self.preparing.add(resource.name)
        try:
            self._check_schema(resource, resource.schema, path=(), is_root=True)
        finally:
            self.preparing.remove(resource.name)
        self.prepared.add(resource.name)

    def _check_schema(
        self,
        resource: _ResourceV2,
        schema: Any,
        *,
        path: tuple[str | int, ...],
        is_root: bool = False,
    ) -> None:
        if type(schema) is bool:
            return
        if type(schema) is not dict:
            _definition(
                "SCHEMA_NODE_INVALID",
                f"узел схемы не является объектом или boolean: {_pointer(path)}",
                path=path,
            )
        unknown = sorted(set(schema) - _SUPPORTED_KEYWORDS)
        if unknown:
            _definition(
                "SCHEMA_KEYWORD_UNSUPPORTED",
                "неподдерживаемые ключи: " + ", ".join(unknown),
                path=path,
            )
        if "$schema" in schema and (
            not is_root or schema["$schema"] != _DRAFT_2020_12
        ):
            _definition(
                "SCHEMA_DIALECT_UNSUPPORTED",
                "$schema разрешён только в корне ресурса",
                path=path,
            )
        if "$id" in schema and (not is_root or schema["$id"] != resource.identity):
            _definition(
                "SCHEMA_ID_UNSUPPORTED",
                "$id разрешён только в корне ресурса",
                path=path,
            )
        for annotation in ("title", "description"):
            if annotation in schema and type(schema[annotation]) is not str:
                _definition(
                    "SCHEMA_KEYWORD_INVALID",
                    f"{annotation} должен быть строкой",
                    path=path,
                )
        if "$ref" in schema:
            if type(schema["$ref"]) is not str:
                _definition(
                    "SCHEMA_REFERENCE_INVALID",
                    "$ref должен быть строкой",
                    path=path,
                )
            self.resolve(resource, schema["$ref"])
        if "type" in schema:
            names = schema["type"]
            names = [names] if type(names) is str else names
            if (
                type(names) is not list
                or not names
                or any(
                    type(name) is not str or name not in _TYPE_NAMES
                    for name in names
                )
                or len(names) != len(set(names))
            ):
                _definition("SCHEMA_TYPE_INVALID", "неверный type", path=path)
        if "enum" in schema and (
            type(schema["enum"]) is not list or not schema["enum"]
        ):
            _definition(
                "SCHEMA_ENUM_INVALID",
                "enum должен быть непустым массивом",
                path=path,
            )
        for name in ("$defs", "properties"):
            if name not in schema:
                continue
            children = schema[name]
            if type(children) is not dict:
                _definition(
                    "SCHEMA_KEYWORD_INVALID",
                    f"{name} должен быть объектом",
                    path=path,
                )
            for child_name, child in children.items():
                self._check_schema(
                    resource,
                    child,
                    path=(*path, name, child_name),
                )
        if "required" in schema:
            required = schema["required"]
            if (
                type(required) is not list
                or any(type(name) is not str for name in required)
                or len(required) != len(set(required))
            ):
                _definition(
                    "SCHEMA_REQUIRED_INVALID",
                    "неверный required",
                    path=path,
                )
        for name in ("allOf", "oneOf", "prefixItems"):
            if name not in schema:
                continue
            children = schema[name]
            if type(children) is not list or not children:
                _definition(
                    "SCHEMA_KEYWORD_INVALID",
                    f"неверный {name}",
                    path=path,
                )
            for index, child in enumerate(children):
                self._check_schema(resource, child, path=(*path, name, index))
        for name in (
            "items",
            "additionalProperties",
            "contains",
            "not",
            "if",
            "then",
            "else",
        ):
            if name in schema:
                self._check_schema(resource, schema[name], path=(*path, name))
        for name in (
            "minContains",
            "maxContains",
            "minItems",
            "maxItems",
            "minLength",
            "maxLength",
            "minProperties",
            "maxProperties",
        ):
            if name in schema and (
                type(schema[name]) is not int or schema[name] < 0
            ):
                _definition(
                    "SCHEMA_BOUND_INVALID",
                    f"неверный {name}",
                    path=path,
                )
        for minimum_name, maximum_name in (
            ("minContains", "maxContains"),
            ("minItems", "maxItems"),
            ("minLength", "maxLength"),
            ("minProperties", "maxProperties"),
        ):
            if (
                minimum_name in schema
                and maximum_name in schema
                and schema[minimum_name] > schema[maximum_name]
            ):
                _definition(
                    "SCHEMA_BOUND_INVALID",
                    f"{minimum_name} превышает {maximum_name}",
                    path=path,
                )
        for name in ("minimum", "maximum"):
            if name in schema and not _is_number(schema[name]):
                _definition(
                    "SCHEMA_BOUND_INVALID",
                    f"неверный {name}",
                    path=path,
                )
        if "uniqueItems" in schema and type(schema["uniqueItems"]) is not bool:
            _definition(
                "SCHEMA_KEYWORD_INVALID",
                "uniqueItems должен быть boolean",
                path=path,
            )
        if "pattern" in schema:
            if type(schema["pattern"]) is not str:
                _definition(
                    "SCHEMA_PATTERN_INVALID",
                    "pattern должен быть строкой",
                    path=path,
                )
            try:
                re.compile(schema["pattern"])
            except re.error as error:
                _definition(
                    "SCHEMA_PATTERN_INVALID",
                    f"неверный pattern: {error}",
                    path=path,
                )
        if "format" in schema and schema["format"] != "date-time":
            _definition(
                "SCHEMA_FORMAT_UNSUPPORTED",
                f"неподдерживаемый format: {schema['format']}",
                path=path,
            )

    def resolve(
        self,
        current: _ResourceV2,
        reference: str,
    ) -> tuple[_ResourceV2, Any]:
        if not reference or "\0" in reference:
            _definition(
                "SCHEMA_REFERENCE_INVALID",
                "пустая или опасная ссылка",
            )
        absolute, fragment = urldefrag(urljoin(current.identity, reference))
        if absolute == current.identity:
            target_resource = current
        else:
            parsed = urlsplit(absolute)
            name = Path(parsed.path).name
            if (
                parsed.scheme != "https"
                or parsed.query
                or _SCHEMA_NAME.fullmatch(name) is None
                or absolute != urljoin(current.identity, name)
            ):
                _definition(
                    "SCHEMA_REFERENCE_EXTERNAL",
                    f"ссылка выходит из каталога схем: {reference}",
                )
            target_resource = self.load(name)
            if target_resource.identity != absolute:
                _definition(
                    "SCHEMA_REFERENCE_ID_MISMATCH",
                    f"$id не совпадает со ссылкой: {reference}",
                )
            self.prepare(target_resource)
        target: Any = target_resource.schema
        if fragment:
            if not fragment.startswith("/") or "%" in fragment:
                _definition(
                    "SCHEMA_REFERENCE_FRAGMENT_UNSUPPORTED",
                    f"неподдерживаемый фрагмент: {reference}",
                )
            for encoded in fragment[1:].split("/"):
                token = encoded.replace("~1", "/").replace("~0", "~")
                if type(target) is dict and token in target:
                    target = target[token]
                elif (
                    type(target) is list
                    and token.isdigit()
                    and int(token) < len(target)
                ):
                    target = target[int(token)]
                else:
                    _definition(
                        "SCHEMA_REFERENCE_UNRESOLVED",
                        f"не найден фрагмент: {reference}",
                    )
        if type(target) not in {dict, bool}:
            _definition(
                "SCHEMA_REFERENCE_TARGET_INVALID",
                f"ссылка ведёт не на схему: {reference}",
            )
        return target_resource, target


def build_closed_json_schema_validator_v2(
    schema_directory: Path,
    root_schema_name: str,
) -> ClosedValidatorV2:
    """Собрать проверяющий объект из закрытого набора соседних схем."""

    if (
        not isinstance(schema_directory, Path)
        or not schema_directory.is_absolute()
    ):
        _definition(
            "SCHEMA_DIRECTORY_INVALID",
            "каталог схем должен быть абсолютным Path",
        )
    try:
        information = schema_directory.lstat()
    except OSError as error:
        _definition(
            "SCHEMA_DIRECTORY_INVALID",
            f"каталог схем недоступен: {error}",
        )
    if not stat.S_ISDIR(information.st_mode) or stat.S_ISLNK(information.st_mode):
        _definition(
            "SCHEMA_DIRECTORY_INVALID",
            "каталог схем небезопасен",
        )
    registry = _RegistryV2(schema_directory)
    root = registry.load(root_schema_name)
    registry.prepare(root)

    def validate(value: Any) -> None:
        _require_json_value_v2(value, path=(), depth=0, active=set())
        _validate(value, root.schema, registry, root, path=(), depth=0)

    return validate


def _require_json_value_v2(
    value: Any,
    *,
    path: tuple[str | int, ...],
    depth: int,
    active: set[int],
) -> None:
    if depth > _MAX_VALIDATION_DEPTH:
        _violation("достигнут предел глубины значения JSON", path)
    if value is None or type(value) in {bool, int, str}:
        return
    if type(value) is float:
        if not math.isfinite(value):
            _violation("число JSON должно быть конечным", path)
        return
    if type(value) not in {list, dict}:
        _violation(
            f"тип {type(value).__name__} не входит в модель данных JSON",
            path,
        )

    identity = id(value)
    if identity in active:
        _violation("циклическое значение не является JSON", path)
    active.add(identity)
    try:
        if type(value) is list:
            for index, item in enumerate(value):
                _require_json_value_v2(
                    item,
                    path=(*path, index),
                    depth=depth + 1,
                    active=active,
                )
            return
        for name, item in value.items():
            if type(name) is not str:
                _violation("ключ объекта JSON не является строкой", path)
            _require_json_value_v2(
                item,
                path=(*path, name),
                depth=depth + 1,
                active=active,
            )
    finally:
        active.remove(identity)


def _validate(
    value: Any,
    schema: Any,
    registry: _RegistryV2,
    resource: _ResourceV2,
    *,
    path: tuple[str | int, ...],
    depth: int,
) -> None:
    if depth > _MAX_VALIDATION_DEPTH:
        _violation("достигнут предел глубины проверки", path)
    if schema is True:
        return
    if schema is False:
        _violation("значение запрещено boolean-схемой", path)
    if "$ref" in schema:
        target_resource, target = registry.resolve(resource, schema["$ref"])
        _validate(
            value,
            target,
            registry,
            target_resource,
            path=path,
            depth=depth + 1,
        )
    for child in schema.get("allOf", ()):
        _validate(value, child, registry, resource, path=path, depth=depth + 1)
    if "oneOf" in schema:
        matches = sum(
            _matches(value, child, registry, resource, path=path, depth=depth + 1)
            for child in schema["oneOf"]
        )
        if matches != 1:
            _violation("значение должно соответствовать ровно одному oneOf", path)
    if "not" in schema and _matches(
        value, schema["not"], registry, resource, path=path, depth=depth + 1
    ):
        _violation("значение запрещено not", path)
    if "if" in schema:
        branch = "then" if _matches(
            value, schema["if"], registry, resource, path=path, depth=depth + 1
        ) else "else"
        if branch in schema:
            _validate(
                value,
                schema[branch],
                registry,
                resource,
                path=path,
                depth=depth + 1,
            )
    if "type" in schema and not _matches_type(value, schema["type"]):
        _violation(f"неверный тип, ожидался {schema['type']}", path)
    if "const" in schema and not _json_equal(value, schema["const"]):
        _violation("значение не совпадает с const", path)
    if "enum" in schema and not any(
        _json_equal(value, candidate) for candidate in schema["enum"]
    ):
        _violation("значение отсутствует в enum", path)

    if type(value) is dict:
        if "minProperties" in schema and len(value) < schema["minProperties"]:
            _violation("слишком мало полей", path)
        if "maxProperties" in schema and len(value) > schema["maxProperties"]:
            _violation("слишком много полей", path)
        if any(type(name) is not str for name in value):
            _violation("ключ объекта не является строкой", path)
        required = schema.get("required", ())
        missing = [name for name in required if name not in value]
        if missing:
            _violation("отсутствуют поля: " + ", ".join(missing), path)
        properties = schema.get("properties", {})
        for name, child in properties.items():
            if name in value:
                _validate(
                    value[name],
                    child,
                    registry,
                    resource,
                    path=(*path, name),
                    depth=depth + 1,
                )
        additional = schema.get("additionalProperties", True)
        for name in sorted(value.keys() - properties.keys()):
            if additional is False:
                _violation(f"неожиданное поле: {name}", path)
            if type(additional) is dict:
                _validate(
                    value[name],
                    additional,
                    registry,
                    resource,
                    path=(*path, name),
                    depth=depth + 1,
                )

    if type(value) is list:
        if "minItems" in schema and len(value) < schema["minItems"]:
            _violation("слишком мало элементов", path)
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            _violation("слишком много элементов", path)
        if schema.get("uniqueItems"):
            seen: set[Any] = set()
            for index, item in enumerate(value):
                marker = _json_key(item)
                if marker in seen:
                    _violation(
                        "элементы должны быть уникальны",
                        (*path, index),
                    )
                seen.add(marker)
        prefix = schema.get("prefixItems", ())
        for index, child in enumerate(prefix[: len(value)]):
            _validate(
                value[index],
                child,
                registry,
                resource,
                path=(*path, index),
                depth=depth + 1,
            )
        if "items" in schema:
            items = schema["items"]
            for index in range(len(prefix), len(value)):
                _validate(
                    value[index],
                    items,
                    registry,
                    resource,
                    path=(*path, index),
                    depth=depth + 1,
                )
        if "contains" in schema:
            count = sum(
                _matches(
                    item,
                    schema["contains"],
                    registry,
                    resource,
                    path=(*path, index),
                    depth=depth + 1,
                )
                for index, item in enumerate(value)
            )
            minimum = schema.get("minContains", 1)
            maximum = schema.get("maxContains")
            if count < minimum or (maximum is not None and count > maximum):
                _violation(
                    "число совпадений contains вне границ",
                    path,
                )

    if type(value) is str:
        if "minLength" in schema and len(value) < schema["minLength"]:
            _violation("строка слишком короткая", path)
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            _violation("строка слишком длинная", path)
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            _violation("строка не соответствует pattern", path)
        if schema.get("format") == "date-time" and not _valid_rfc3339(value):
            _violation("строка не соответствует date-time", path)

    if _is_number(value):
        if "minimum" in schema and value < schema["minimum"]:
            _violation("число меньше minimum", path)
        if "maximum" in schema and value > schema["maximum"]:
            _violation("число больше maximum", path)


def _matches(
    value: Any,
    schema: Any,
    registry: _RegistryV2,
    resource: _ResourceV2,
    *,
    path: tuple[str | int, ...],
    depth: int,
) -> bool:
    try:
        _validate(value, schema, registry, resource, path=path, depth=depth)
    except ClosedJsonSchemaV2Error as error:
        if error.code != "VALUE_INVALID":
            raise
        return False
    return True


def _matches_type(value: Any, expected: Any) -> bool:
    names = [expected] if type(expected) is str else expected
    return any(
        (name == "object" and type(value) is dict)
        or (name == "array" and type(value) is list)
        or (name == "string" and type(value) is str)
        or (name == "integer" and _is_integer(value))
        or (name == "number" and _is_number(value))
        or (name == "boolean" and type(value) is bool)
        or (name == "null" and value is None)
        for name in names
    )


def _is_integer(value: Any) -> bool:
    return type(value) is int or (
        type(value) is float and math.isfinite(value) and value.is_integer()
    )


def _is_number(value: Any) -> bool:
    return type(value) in {int, float} and not (
        type(value) is float and not math.isfinite(value)
    )


def _json_equal(left: Any, right: Any) -> bool:
    if _is_number(left) and _is_number(right):
        return left == right
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(
            _json_equal(left[key], right[key]) for key in left
        )
    if type(left) is list:
        return len(left) == len(right) and all(
            _json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    return left == right


def _json_key(value: Any) -> Any:
    if _is_number(value):
        return ("number", value)
    if value is None:
        return ("null",)
    if type(value) is bool:
        return ("boolean", value)
    if type(value) is str:
        return ("string", value)
    if type(value) is list:
        return ("array", tuple(_json_key(item) for item in value))
    if type(value) is dict:
        return (
            "object",
            tuple(sorted((name, _json_key(item)) for name, item in value.items())),
        )
    return (type(value).__name__, repr(value))


def _valid_rfc3339(value: str) -> bool:
    match = _RFC3339.fullmatch(value.upper())
    if match is None:
        return False
    year, month, day = map(int, match.groups())
    if year == 0:
        return False
    try:
        maximum_day = calendar.monthrange(year, month)[1]
    except calendar.IllegalMonthError:
        return False
    return 1 <= day <= maximum_day


def _unique_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            _definition("SCHEMA_JSON_DUPLICATE_KEY", f"повтор ключа: {name}")
        result[name] = value
    return result


def _raise_json_constant(value: str) -> Any:
    raise json.JSONDecodeError(
        f"недопустимая константа {value}",
        value,
        0,
    )


def _pointer(path: Sequence[str | int]) -> str:
    if not path:
        return "/"
    return "/" + "/".join(
        str(item).replace("~", "~0").replace("/", "~1") for item in path
    )


def _definition(
    code: str,
    message: str,
    *,
    path: Sequence[str | int] = (),
) -> None:
    raise ClosedJsonSchemaV2Error(code, message, path=path)


def _violation(message: str, path: Sequence[str | int]) -> None:
    raise ClosedJsonSchemaV2Error("VALUE_INVALID", message, path=path)
