"""Чистый разбор Markdown и статического контракта состояний."""

from __future__ import annotations

import ast
import html
import re
import string
import unicodedata
from array import array
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from typing import Mapping, Sequence
from urllib.parse import unquote


REFERENCE_DEFINITION_PATTERN = re.compile(
    r"^ {0,3}\[([^\]\n]{1,999})]:[ \t]*(\S.*)$"
)
REFERENCE_DEFINITION_START_PATTERN = re.compile(
    r"^ {0,3}\[([^\]\n]{1,999})]:(.*)$"
)
ATX_HEADING_PATTERN = re.compile(
    r"^ {0,3}(#{1,6})(?:[ \t]+(.*?)|[ \t]*)$"
)
SETEXT_HEADING_PATTERN = re.compile(
    r"^ {0,3}(?:=+|-+)[ \t]*$"
)
FENCE_OPEN_PATTERN = re.compile(
    r"^( {0,3})(`{3,}|~{3,})(.*)$"
)
ORDERED_LIST_PATTERN = re.compile(r"^ {0,3}\d{1,9}[.)][ \t]+")
EMPTY_LIST_PATTERN = re.compile(
    r"^ {0,3}(?:[-+*]|\d{1,9}[.)])[ \t]*$"
)
THEMATIC_BREAK_PATTERN = re.compile(
    r"^ {0,3}(?:(?:\*[ \t]*){3,}|"
    r"(?:_[ \t]*){3,}|(?:-[ \t]*){3,})$"
)
HTML_NAME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9-]*")
HTML_ATTRIBUTE_NAME_PATTERN = re.compile(
    r"[A-Za-z_:][A-Za-z0-9_.:-]*"
)
ANGLE_AUTOLINK_CANDIDATE_PATTERN = re.compile(r"<([^<>\x00-\x20]+)>")
INLINE_DECLARATION_START_PATTERN = re.compile(
    r"<![A-Z]+(?=[ \t\v\f\r\n])"
)
EXTENDED_URL_AUTOLINK_PATTERN = re.compile(
    r"(?:"
    r"https?://[^\s<>]+"
    r"|www\.[^\s<>]+"
    r")",
    re.IGNORECASE,
)
EMAIL_AUTOLINK_CANDIDATE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._+-])"
    r"[A-Za-z0-9._+-]+"
    r"@[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*"
    r"(?![A-Za-z0-9_-])"
)
STATE_NAME_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*")
MARKDOWN_ESCAPABLE = frozenset(string.punctuation)
RAW_HTML_TAGS = frozenset({"pre", "script", "style", "textarea"})
TAGFILTER_TAGS = frozenset(
    {
        "title",
        "textarea",
        "style",
        "xmp",
        "iframe",
        "noembed",
        "noframes",
        "script",
        "plaintext",
    }
)
RAW_HTML_BLOCK_TAGS = frozenset(
    {
        "address",
        "article",
        "aside",
        "base",
        "basefont",
        "blockquote",
        "body",
        "caption",
        "center",
        "col",
        "colgroup",
        "dd",
        "details",
        "dialog",
        "dir",
        "div",
        "dl",
        "dt",
        "fieldset",
        "figcaption",
        "figure",
        "footer",
        "form",
        "frame",
        "frameset",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "head",
        "header",
        "hr",
        "html",
        "iframe",
        "legend",
        "li",
        "link",
        "main",
        "menu",
        "menuitem",
        "nav",
        "noframes",
        "ol",
        "optgroup",
        "option",
        "p",
        "param",
        "search",
        "section",
        "source",
        "summary",
        "table",
        "tbody",
        "td",
        "tfoot",
        "th",
        "thead",
        "title",
        "tr",
        "track",
        "ul",
    }
)
ROOT_SECTION_ORDER = (
    "Быстрые маршруты",
    "Планы и история решений",
    "Совместимость",
)
ROOT_TABLE_CONTRACTS = {
    "Быстрые маршруты": (
        ("Задача", "Состояние", "Куда перейти"),
        2,
    ),
    "Планы и история решений": (
        ("Документ", "Назначение"),
        0,
    ),
}
MAX_INLINE_DESTINATION = 8192
MAX_INLINE_PARENTHESIS_DEPTH = 32
LINK_WHITESPACE = " \t\r\n"
CANONICAL_STATE_TAIL = """
@dataclass
class StateTransitionError(ValueError):
    before: RouteState
    after: RouteState

    def __str__(self) -> str:
        return f"invalid route transition: {self.before} -> {self.after}"


def assert_transition(before: RouteState, after: RouteState) -> None:
    if after not in ALLOWED_TRANSITIONS[before]:
        raise StateTransitionError(before, after)


def is_terminal(state: RouteState) -> bool:
    return state in TERMINAL_STATES
"""


@dataclass(frozen=True)
class Link:
    target: str
    line: int
    navigable: bool = True


@dataclass(frozen=True)
class Fence:
    language: str
    content: str
    line: int


@dataclass(frozen=True)
class MarkdownDocument:
    links: tuple[Link, ...]
    anchors: frozenset[str]
    fences: tuple[Fence, ...]
    unclosed_fence_line: int | None


@dataclass(frozen=True)
class _HtmlTag:
    name: str
    attributes: Mapping[str, str]
    closing: bool
    self_closing: bool
    end: int


@dataclass(frozen=True)
class _ContainerMarker:
    kind: str
    continuation_indent: int = 0


@dataclass(frozen=True)
class _LineContext:
    lines: tuple[str, ...]
    boundaries: tuple[bool, ...]


@dataclass(frozen=True)
class _RawHtmlBlock:
    start: int
    end: int
    block_type: int
    tag_name: str | None = None


@dataclass(frozen=True)
class _MarkdownLinkSyntax:
    opening: int
    label_end: int
    syntax_end: int
    image: bool


def _markdown_splitlines(
    text: str,
    *,
    keepends: bool = False,
) -> list[str]:
    if not text:
        return []
    if "\r" not in text:
        parts = text.split("\n")
        if keepends:
            lines = [
                part + "\n"
                for part in parts[:-1]
            ]
            if parts[-1]:
                lines.append(parts[-1])
            return lines
        if not parts[-1]:
            parts.pop()
        return parts

    lines: list[str] = []
    start = 0
    for ending in re.finditer(r"\r\n|\r|\n", text):
        lines.append(
            text[start:ending.end()]
            if keepends
            else text[start:ending.start()]
        )
        start = ending.end()
    if start < len(text):
        lines.append(text[start:])
    return lines


def _is_markdown_blank(value: str) -> bool:
    return not value.strip(LINK_WHITESPACE)


def parse_markdown(text: str) -> MarkdownDocument:
    if (
        not any(
            marker in text
            for marker in ("[", "`", "~", "#", "=", "-")
        )
        and not ("<" in text and ">" in text)
    ):
        return MarkdownDocument(
            links=(),
            anchors=frozenset(),
            fences=(),
            unclosed_fence_line=None,
        )
    line_context = _line_context(text)
    block_mask, fences, unclosed_line = _block_mask_and_fences(text)
    line_starts = _line_starts(text)
    (
        markdown_mask,
        heading_mask,
        html_links,
        explicit_anchors,
        _angle_autolinks,
    ) = _mask_html_and_extract_links(
        text,
        block_mask,
        line_starts,
        line_context,
    )
    visible = _masked_text(text, markdown_mask)
    heading_visible = _heading_visible_text(text, heading_mask)
    definitions, definition_lines = _reference_definition_data(visible)
    headings = _headings(heading_visible, definition_lines)
    links = [
        link
        for link in html_links
        if link.line not in definition_lines
    ]
    for target, navigable, position in _markdown_links(
        visible,
        definitions,
        line_context,
    ):
        line_number = _line_number(line_starts, position)
        if line_number in definition_lines:
            continue
        links.append(
            Link(
                target=target,
                line=line_number,
                navigable=navigable,
            )
        )

    return MarkdownDocument(
        links=tuple(links),
        anchors=frozenset(
            explicit_anchors
            | _heading_anchors(headings, definitions)
        ),
        fences=tuple(fences),
        unclosed_fence_line=unclosed_line,
    )


def root_catalog_structure_errors(text: str) -> tuple[str, ...]:
    lines = _markdown_splitlines(text)
    line_context = _line_context(text)
    block_mask, _fences, _unclosed = _block_mask_and_fences(text)
    (
        _markdown_mask,
        structure_mask,
        _html_links,
        _explicit_anchors,
        _angle_autolinks,
    ) = _mask_html_and_extract_links(
        text,
        block_mask,
        _line_starts(text),
        line_context,
    )
    structure_text = _masked_text(
        text,
        structure_mask,
    )
    structure_lines = _markdown_splitlines(structure_text)
    nonblank = [
        (index, line)
        for index, line in enumerate(structure_lines, start=1)
        if not _is_markdown_blank(line)
    ]
    errors: list[str] = []
    if not nonblank or not re.fullmatch(r"# [^#].*", nonblank[0][1]):
        errors.append("первая содержательная строка должна быть заголовком H1")
        return tuple(errors)

    headings: list[tuple[int, int, str]] = []
    for line_number, line in nonblank:
        match = re.match(
            r"^ {0,3}(#{1,6})(?:[ \t]+(.+?)|[ \t]*)$",
            line,
        )
        if match:
            headings.append(
                (
                    line_number,
                    len(match.group(1)),
                    (match.group(2) or "").strip(" \t"),
                )
            )
        if ORDERED_LIST_PATTERN.match(line):
            errors.append(
                f"строка {line_number}: нумерованные инструкции запрещены"
            )

    if sum(level == 1 for _line, level, _text in headings) != 1:
        errors.append("должен быть ровно один заголовок H1")
    if any(level > 2 for _line, level, _text in headings):
        errors.append("в корневом каталоге разрешены только H1 и H2")

    level_two = [
        (line_number, text_value)
        for line_number, level, text_value in headings
        if level == 2
    ]
    if not level_two:
        definitions = _reference_definitions(text)
        for line_number, line in nonblank[1:]:
            stripped = line.strip(" \t")
            definition = REFERENCE_DEFINITION_PATTERN.fullmatch(
                stripped
            )
            if (
                definition is not None
                and _link_destination(definition.group(2)) is not None
            ):
                continue
            list_match = re.fullmatch(
                r"[-*+][ \t]+(.+)",
                stripped,
            )
            candidate = (
                list_match.group(1)
                if list_match is not None
                else stripped
            )
            links = _markdown_links(candidate, definitions)
            navigable = [
                target
                for target, is_navigable, _position in links
                if is_navigable
            ]
            link_label = _exact_markdown_link_label(
                candidate,
                definitions,
            )
            if (
                len(navigable) != 1
                or link_label is None
                or _contains_gfm_autolink(
                    link_label,
                    include_extended=False,
                )
            ):
                errors.append(
                    (
                        f"строка {line_number}: простой каталог может "
                        "содержать только одну явную навигационную ссылку"
                    )
                )
        return tuple(errors)

    observed_sections = tuple(text_value for _line, text_value in level_two)
    if observed_sections != ROOT_SECTION_ORDER:
        errors.append(
            (
                "разделы H2 должны идти строго как "
                f"{list(ROOT_SECTION_ORDER)}"
            )
        )
        return tuple(errors)

    section_starts = {
        text_value: line_number
        for line_number, text_value in level_two
    }
    definitions = _reference_definitions(text)
    links_by_line: dict[int, list[Link]] = {}
    for link in parse_markdown(text).links:
        links_by_line.setdefault(link.line, []).append(link)
    first_section_line = level_two[0][0]
    preamble = lines[1 : first_section_line - 1]
    if not _is_single_visible_paragraph(preamble):
        errors.append("до первого раздела должен быть один вводный абзац")

    for index, section in enumerate(ROOT_SECTION_ORDER):
        start = section_starts[section]
        end = (
            level_two[index + 1][0] - 1
            if index + 1 < len(level_two)
            else len(lines)
        )
        content = lines[start:end]
        if section in ROOT_TABLE_CONTRACTS:
            headers, link_cell = ROOT_TABLE_CONTRACTS[section]
            errors.extend(
                _root_table_errors(
                    section,
                    tuple(
                        (start + offset, line)
                        for offset, line in enumerate(
                            content,
                            start=1,
                        )
                    ),
                    headers,
                    link_cell,
                    definitions,
                    links_by_line,
                )
            )
        else:
            if not _is_single_visible_paragraph(content):
                errors.append(
                    "раздел «Совместимость» должен быть одним абзацем"
                )
            if any(
                "[" in line or "]" in line
                for line in content
            ):
                errors.append(
                    "раздел «Совместимость» не должен содержать "
                    "псевдоссылки"
                )
            if _contains_visible_gfm_table("\n".join(content)):
                errors.append(
                    "раздел «Совместимость» не должен содержать таблицу"
                )
            if _contains_visible_html_table("\n".join(content)):
                errors.append(
                    "раздел «Совместимость» не должен содержать "
                    "HTML-таблицу"
                )
    return tuple(errors)


def _root_table_errors(
    section: str,
    numbered_lines: Sequence[tuple[int, str]],
    headers: Sequence[str],
    link_cell: int,
    definitions: Mapping[str, str],
    links_by_line: Mapping[int, Sequence[Link]],
) -> list[str]:
    content = list(numbered_lines)
    while content and _is_markdown_blank(content[0][1]):
        content.pop(0)
    while content and _is_markdown_blank(content[-1][1]):
        content.pop()
    expected_header = "| " + " | ".join(headers) + " |"
    expected_separator = "|" + "|".join("---" for _ in headers) + "|"
    errors: list[str] = []
    if len(content) < 3:
        return [
            (
                f"раздел «{section}» должен содержать заголовок, "
                "разделитель и хотя бы одну строку данных"
            )
        ]
    if content[0][1] != expected_header:
        errors.append(
            (
                f"раздел «{section}»: ожидается точный заголовок "
                f"таблицы {expected_header!r}"
            )
        )
    if content[1][1] != expected_separator:
        errors.append(
            (
                f"раздел «{section}»: ожидается точный разделитель "
                f"таблицы {expected_separator!r}"
            )
        )

    for line_number, line in content[2:]:
        cells = _strict_root_table_cells(line)
        if cells is None or len(cells) != len(headers):
            errors.append(
                (
                    f"раздел «{section}», строка {line_number}: "
                    f"ожидается ровно {len(headers)} ячейки"
                )
            )
            continue
        if any(not cell for cell in cells):
            errors.append(
                (
                    f"раздел «{section}», строка {line_number}: "
                    "пустые ячейки запрещены"
                )
            )
        if any(
            _contains_visible_html_table(
                cell,
                inline_context=True,
            )
            for cell in cells
        ):
            errors.append(
                (
                    f"раздел «{section}», строка {line_number}: "
                    "HTML-таблица внутри ячейки запрещена"
                )
            )
        row_links = tuple(links_by_line.get(line_number, ()))
        if len(row_links) != 1 or not row_links[0].navigable:
            errors.append(
                (
                    f"раздел «{section}», строка {line_number}: "
                    "нужна ровно одна навигационная ссылка"
                )
            )
        link_label = _exact_markdown_link_label(
            cells[link_cell],
            definitions,
        )
        if link_label is None:
            errors.append(
                (
                    f"раздел «{section}», строка {line_number}: "
                    f"ячейка {link_cell + 1} должна целиком быть "
                    "Markdown-ссылкой"
                )
            )
        if any(
            _contains_gfm_autolink(cell)
            for index, cell in enumerate(cells)
            if index != link_cell
        ) or (
            link_label is not None
            and _contains_gfm_autolink(
                link_label,
                include_extended=False,
            )
        ):
            errors.append(
                (
                    f"раздел «{section}», строка {line_number}: "
                    "нужна ровно одна навигационная ссылка"
                )
            )
    return errors


def _strict_root_table_cells(line: str) -> tuple[str, ...] | None:
    if not line or line[0] != "|" or line[-1] != "|":
        return None
    escaped = _escape_flags(line)
    separators = [
        index
        for index, character in enumerate(line)
        if character == "|" and not escaped[index]
    ]
    if (
        len(separators) < 2
        or separators[0] != 0
        or separators[-1] != len(line) - 1
    ):
        return None
    return tuple(
        line[start + 1 : end].strip(" \t")
        for start, end in zip(separators, separators[1:])
    )


def _contains_unescaped_pipe(line: str) -> bool:
    escaped = _escape_flags(line)
    return any(
        character == "|"
        and not escaped[index]
        for index, character in enumerate(line)
    )


def _gfm_table_cells(line: str) -> tuple[str, ...] | None:
    escaped = _escape_flags(line)
    separators = [
        index
        for index, character in enumerate(line)
        if (
            character == "|"
            and not escaped[index]
        )
    ]
    if not separators:
        return None
    cells: list[str] = []
    start = 0
    for separator in separators:
        cells.append(line[start:separator].strip(" \t"))
        start = separator + 1
    cells.append(line[start:].strip(" \t"))
    if separators[0] == 0:
        cells.pop(0)
    if separators[-1] == len(line) - 1:
        cells.pop()
    return tuple(cells)


def _contains_visible_gfm_table(text: str) -> bool:
    if "|" not in text or "-" not in text:
        return False
    block_mask, _fences, _unclosed = _block_mask_and_fences(text)
    visible_mask = bytearray(block_mask)
    for block in _raw_html_block_ranges(text, block_mask):
        _mask_range(visible_mask, block.start, block.end)
    visible = _masked_text(text, visible_mask)
    return bool(
        _gfm_table_line_indexes(_markdown_splitlines(visible))
    )


def _inline_link_destination_mask(
    text: str,
    block_mask: bytearray,
    raw_blocks: Sequence[_RawHtmlBlock],
) -> bytearray:
    mask = bytearray(len(text))
    escaped = _escape_flags(text)
    closing_parentheses = _unescaped_character_positions(
        text,
        ")",
        escaped,
    )
    raw_mask = bytearray(len(text))
    for block in raw_blocks:
        raw_mask[block.start:block.end] = (
            b"\x01" * (block.end - block.start)
        )
    cursor = 0
    while cursor < len(text):
        label_end = text.find("](", cursor)
        if label_end < 0:
            break
        opening = label_end + 1
        if (
            block_mask[label_end]
            and block_mask[opening]
            and not raw_mask[label_end]
            and not raw_mask[opening]
        ):
            destination = _inline_destination(
                text,
                opening,
                closing_parentheses,
            )
            if destination is not None:
                _target, destination_end = destination
                end = destination_end + 1
                if (
                    all(block_mask[opening:end])
                    and not any(raw_mask[opening:end])
                ):
                    mask[opening:end] = b"\x01" * (end - opening)
                    cursor = end
                    continue
        cursor = opening + 1
    return mask


def _contains_visible_html_table(
    text: str,
    *,
    inline_context: bool = False,
) -> bool:
    if "<" not in text or "table" not in text.casefold():
        return False
    block_mask, _fences, _unclosed = _block_mask_and_fences(text)
    code_span_endings = _code_span_endings(text, block_mask)
    raw_blocks = (
        []
        if inline_context
        else _raw_html_block_ranges(text, block_mask)
    )
    link_destination_mask = _inline_link_destination_mask(
        text,
        block_mask,
        raw_blocks,
    )
    line_context = _line_context(text)
    line_starts = _line_starts(text)
    inline_boundaries = [
        line_starts[index + 1]
        for index, boundary in enumerate(line_context.boundaries)
        if boundary and index + 1 < len(line_starts)
    ]
    html_visible = bytearray(block_mask)
    for boundary in inline_boundaries:
        if boundary > 0:
            html_visible[boundary - 1] = 0
    raw_index = 0
    html_text = _container_prefix_masked_text(text)
    escaped = _escape_flags(text)
    inline_html_closers = _inline_html_closer_index(text)
    raw_special_ends = {
        block.start: _raw_special_block_content_end(
            text,
            block,
            inline_html_closers,
        )
        for block in raw_blocks
        if block.block_type in {2, 3, 4, 5}
    }
    cursor = 0
    while cursor < len(text):
        while (
            raw_index < len(raw_blocks)
            and cursor >= raw_blocks[raw_index].end
        ):
            raw_index += 1
        raw_block = (
            raw_blocks[raw_index]
            if (
                raw_index < len(raw_blocks)
                and raw_blocks[raw_index].start
                <= cursor
                < raw_blocks[raw_index].end
            )
            else None
        )
        inside_raw_html = raw_block is not None
        if (
            raw_block is not None
            and raw_block.block_type in {2, 3, 4, 5}
            and cursor < raw_special_ends[raw_block.start]
        ):
            cursor = raw_special_ends[raw_block.start]
            continue
        if not inside_raw_html and not block_mask[cursor]:
            cursor += 1
            continue
        code_span_end = code_span_endings.get(cursor)
        if (
            not inside_raw_html
            and code_span_end is not None
        ):
            cursor = code_span_end
            continue
        if not inside_raw_html and link_destination_mask[cursor]:
            cursor += 1
            continue
        if (
            text[cursor] != "<"
            or (not inside_raw_html and escaped[cursor])
        ):
            cursor += 1
            continue
        boundary_index = bisect_right(inline_boundaries, cursor)
        scope_end = (
            raw_block.end
            if raw_block is not None
            else (
                inline_boundaries[boundary_index]
                if boundary_index < len(inline_boundaries)
                else len(text)
            )
        )
        special_end = _inline_raw_html_end(
            text,
            cursor,
            scope_end,
            inline_html_closers,
        )
        if special_end is not None:
            cursor = special_end
            continue
        tag = (
            _raw_html_tag_token(html_text, cursor, scope_end)
            if inside_raw_html
            else _parse_html_tag(
                html_text,
                cursor,
                html_visible,
                scope_end,
            )
        )
        if tag is None:
            cursor += 1
            continue
        if tag.name == "table" and not tag.closing:
            return True
        cursor = tag.end
    return False


def _raw_html_tag_token(
    text: str,
    start: int,
    limit: int,
) -> _HtmlTag | None:
    cursor = start + 1
    closing = False
    if cursor < limit and text[cursor] == "/":
        closing = True
        cursor += 1
    name_match = HTML_NAME_PATTERN.match(text, cursor)
    if name_match is None:
        return None
    name = name_match.group(0).casefold()
    cursor = name_match.end()
    if (
        cursor < limit
        and text[cursor] not in " \t\f\r\n/>"
    ):
        return None
    quote: str | None = None
    while cursor < limit:
        character = text[cursor]
        if quote is not None:
            if character == quote:
                quote = None
            cursor += 1
            continue
        if character in {'"', "'"}:
            quote = character
            cursor += 1
            continue
        if character == ">":
            return _HtmlTag(
                name=name,
                attributes={},
                closing=closing,
                self_closing=(
                    cursor > start and text[cursor - 1] == "/"
                ),
                end=cursor + 1,
            )
        cursor += 1
    return None


def _contains_gfm_autolink(
    text: str,
    *,
    include_extended: bool = True,
) -> bool:
    line_context = _line_context(text)
    block_mask, _fences, _unclosed = _block_mask_and_fences(text)
    (
        markdown_mask,
        _heading_mask,
        _links,
        _anchors,
        angle_autolinks,
    ) = (
        _mask_html_and_extract_links(
            text,
            block_mask,
            _line_starts(text),
            line_context,
        )
    )
    if angle_autolinks:
        return True
    candidate = _masked_text(text, markdown_mask)
    if not include_extended:
        return False
    if any(
        _is_extended_url_autolink(match.group(0))
        and _is_extended_url_boundary(
            candidate,
            match.start(),
            match.group(0),
        )
        for match in EXTENDED_URL_AUTOLINK_PATTERN.finditer(candidate)
    ):
        return True
    return any(
        _is_extended_email_autolink(match.group(0))
        for match in EMAIL_AUTOLINK_CANDIDATE_PATTERN.finditer(candidate)
    )


def _is_uri_autolink(value: str) -> bool:
    return (
        re.fullmatch(
            r"[A-Za-z][A-Za-z0-9+.-]{1,31}:"
            r"[^<>\x00-\x20\x7f]*",
            value,
        )
        is not None
    )


def _is_extended_url_autolink(value: str) -> bool:
    original = value
    value = value.rstrip("?!.,:*_~")
    if not value:
        return False
    if original.startswith("www.") and value == "www":
        return True
    lowered = value.casefold()
    if lowered.startswith("www."):
        if not value.startswith("www."):
            return False
        authority = value[4:]
        minimum_segments = 1
        require_alphanumeric_start = False
    elif lowered.startswith("https://"):
        authority = value[8:]
        minimum_segments = 1
        require_alphanumeric_start = True
    elif lowered.startswith("http://"):
        authority = value[7:]
        minimum_segments = 1
        require_alphanumeric_start = True
    else:
        return False
    authority = re.split(r"[/#?]", authority, maxsplit=1)[0]
    if not authority:
        return False
    host_source = authority.rsplit("@", 1)[-1]
    host_match = re.match(
        r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*",
        host_source,
    )
    if host_match is None:
        return False
    host = host_match.group(0)
    segments = host.split(".")
    return bool(
        len(segments) >= minimum_segments
        and (
            not require_alphanumeric_start
            or host[0].isalnum()
        )
        and all(
            re.fullmatch(r"[A-Za-z0-9_-]+", segment) is not None
            for segment in segments
        )
        and all("_" not in segment for segment in segments[-2:])
    )


def _is_extended_url_boundary(
    text: str,
    start: int,
    value: str | None = None,
) -> bool:
    if start == 0:
        return True
    previous = text[start - 1]
    if value is not None and value.casefold().startswith("www."):
        return previous.isspace() or previous in "*_~("
    return not (
        previous == "["
        or
        "A" <= previous <= "Z"
        or "a" <= previous <= "z"
    )


def _is_standard_email_autolink(value: str) -> bool:
    if value.count("@") != 1:
        return False
    local, domain = value.rsplit("@", 1)
    if (
        not local
        or re.fullmatch(
            r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+",
            local,
        )
        is None
    ):
        return False
    labels = domain.split(".")
    if not labels or any(not label for label in labels):
        return False
    for label in labels:
        if (
            len(label) > 63
            or re.fullmatch(r"[A-Za-z0-9-]+", label) is None
            or label.startswith("-")
            or label.endswith("-")
        ):
            return False
    return True


def _is_extended_email_autolink(value: str) -> bool:
    if value.count("@") != 1:
        return False
    local, domain = value.rsplit("@", 1)
    if (
        not local
        or re.fullmatch(r"[A-Za-z0-9._+-]+", local) is None
    ):
        return False
    labels = domain.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return False
    if any(
        re.fullmatch(r"[A-Za-z0-9_-]+", label) is None
        for label in labels
    ):
        return False
    return bool(
        not domain.endswith(("-", "_"))
        and re.search(r"[A-Za-z]$", labels[-1])
    )


def parse_route_contract(
    source: str,
    *,
    filename: str,
) -> tuple[set[str], set[tuple[str, str]], set[str]]:
    tree = ast.parse(source, filename=filename)
    (
        route_class,
        terminal_expression,
        transition_expression,
    ) = _canonical_contract_nodes(tree)
    members = _route_state_members(route_class)
    terminals = _state_set(terminal_expression, members)
    pairs, transition_keys = _transition_pairs(
        transition_expression,
        members,
        terminals,
    )
    states = set(members.values())
    if transition_keys != states:
        missing = sorted(states - transition_keys)
        extra = sorted(transition_keys - states)
        raise ValueError(
            (
                "ключи ALLOWED_TRANSITIONS не совпадают с RouteState: "
                f"отсутствуют={missing}; лишние={extra}"
            )
        )
    return states, pairs, terminals


def _canonical_contract_nodes(
    tree: ast.Module,
) -> tuple[ast.ClassDef, ast.expr, ast.expr]:
    if len(tree.body) != 10:
        raise ValueError(
            "модуль состояний должен содержать ровно десять "
            "канонических объявлений"
        )
    documentation = tree.body[0]
    if not (
        isinstance(documentation, ast.Expr)
        and isinstance(documentation.value, ast.Constant)
        and isinstance(documentation.value.value, str)
    ):
        raise ValueError(
            "модуль состояний должен начинаться со строки документации"
        )
    _validate_exact_import(
        tree.body[1],
        module="__future__",
        name="annotations",
    )
    _validate_exact_import(
        tree.body[2],
        module="dataclasses",
        name="dataclass",
    )
    _validate_exact_import(
        tree.body[3],
        module="enum",
        name="StrEnum",
    )

    route_class = tree.body[4]
    if not (
        isinstance(route_class, ast.ClassDef)
        and route_class.name == "RouteState"
    ):
        raise ValueError(
            "пятым объявлением должен быть класс RouteState"
        )

    terminal_statement = tree.body[5]
    terminal_assignment = _simple_assignment(terminal_statement)
    if not (
        isinstance(terminal_statement, ast.Assign)
        and terminal_assignment is not None
        and terminal_assignment[0] == "TERMINAL_STATES"
    ):
        raise ValueError(
            "шестым объявлением должен быть TERMINAL_STATES"
        )

    transition_statement = tree.body[6]
    transition_assignment = _simple_assignment(transition_statement)
    if not (
        isinstance(transition_statement, ast.AnnAssign)
        and transition_statement.simple == 1
        and transition_assignment is not None
        and transition_assignment[0] == "ALLOWED_TRANSITIONS"
        and _is_transition_annotation(
            transition_statement.annotation
        )
    ):
        raise ValueError(
            "седьмым объявлением должен быть канонический "
            "ALLOWED_TRANSITIONS"
        )

    expected_tail = ast.parse(CANONICAL_STATE_TAIL).body
    if [
        _ast_shape(node)
        for node in tree.body[7:]
    ] != [
        _ast_shape(node)
        for node in expected_tail
    ]:
        raise ValueError(
            "вспомогательный хвост модуля состояний неканоничен"
        )
    return (
        route_class,
        terminal_assignment[1],
        transition_assignment[1],
    )


def _validate_exact_import(
    statement: ast.stmt,
    *,
    module: str,
    name: str,
) -> None:
    if not (
        isinstance(statement, ast.ImportFrom)
        and statement.level == 0
        and statement.module == module
        and len(statement.names) == 1
        and statement.names[0].name == name
        and statement.names[0].asname is None
    ):
        raise ValueError(
            f"ожидался точный импорт from {module} import {name}"
        )


def _ast_shape(node: ast.AST) -> str:
    return ast.dump(
        node,
        annotate_fields=True,
        include_attributes=False,
    )


def _block_mask_and_fences(
    text: str,
) -> tuple[bytearray, list[Fence], int | None]:
    mask = bytearray(b"\x01") * len(text)
    fences: list[Fence] = []
    active: tuple[
        str,
        int,
        int,
        str,
        int,
        tuple[_ContainerMarker, ...],
    ] | None = None
    active_content: list[str] = []
    offset = 0
    paragraph_open = False
    paragraph_signature: tuple[_ContainerMarker, ...] = ()

    for line_number, raw_line in enumerate(
        _markdown_splitlines(text, keepends=True),
        start=1,
    ):
        source_content = raw_line.rstrip("\r\n")
        content, prefix, signature = _container_content(source_content)
        explicit_list_item = (
            prefix > 0
            and any(
                marker.kind == "list"
                for marker in signature
            )
        )
        if explicit_list_item:
            paragraph_open = False
            paragraph_signature = signature
        line_end = offset + len(raw_line)
        if (
            not explicit_list_item
            and signature != paragraph_signature
            and any(
                marker.kind == "list"
                for marker in paragraph_signature
            )
        ):
            continued_paragraph = _continued_container_content(
                source_content,
                paragraph_signature,
            )
            if continued_paragraph is not None:
                content, prefix = continued_paragraph
                signature = paragraph_signature
        if signature != paragraph_signature:
            paragraph_open = False
            paragraph_signature = signature
        if active is not None:
            (
                marker,
                marker_length,
                indent,
                language,
                opened,
                active_signature,
            ) = active
            same_container = (
                signature == active_signature
                and not explicit_list_item
            )
            if not same_container:
                continued = (
                    None
                    if (
                        (
                            explicit_list_item
                            and signature == active_signature
                        )
                        or not any(
                            marker.kind == "list"
                            for marker in active_signature
                        )
                    )
                    else _continued_container_content(
                        source_content,
                        active_signature,
                    )
                )
                if continued is not None:
                    content, _prefix = continued
                    signature = active_signature
                    same_container = True
            if same_container:
                _mask_range(mask, offset, line_end)
                if _is_fence_close(content, marker, marker_length):
                    fences.append(
                        Fence(
                            language=language,
                            content="\n".join(active_content),
                            line=opened,
                        )
                    )
                    active = None
                    active_content = []
                    paragraph_open = False
                else:
                    active_content.append(
                        _strip_indent(content, indent)
                    )
                offset = line_end
                continue
            fences.append(
                Fence(
                    language=language,
                    content="\n".join(active_content),
                    line=opened,
                )
            )
            active = None
            active_content = []
            paragraph_open = False

        opening = _fence_open(content)
        if opening is not None:
            marker, marker_length, indent, language = opening
            _mask_range(mask, offset, line_end)
            active = (
                marker,
                marker_length,
                indent,
                language,
                line_number,
                signature,
            )
            active_content = []
            paragraph_open = False
            offset = line_end
            continue

        if _is_markdown_blank(content):
            paragraph_open = False
        elif (
            ATX_HEADING_PATTERN.match(content)
            or THEMATIC_BREAK_PATTERN.match(content)
            or EMPTY_LIST_PATTERN.match(content)
        ):
            paragraph_open = False
        elif (
            SETEXT_HEADING_PATTERN.match(content)
            and paragraph_open
        ):
            paragraph_open = False
        elif _indent_columns(content) >= 4 and not paragraph_open:
            _mask_range(mask, offset, line_end)
        else:
            paragraph_open = True
        offset = line_end

    if active is not None:
        (
            _marker,
            _length,
            _indent,
            language,
            opened,
            _signature,
        ) = active
        fences.append(
            Fence(
                language=language,
                content="\n".join(active_content),
                line=opened,
            )
        )
        return mask, fences, opened
    return mask, fences, None


def _container_content(
    line: str,
) -> tuple[str, int, tuple[_ContainerMarker, ...]]:
    cursor = 0
    signature: list[_ContainerMarker] = []
    while cursor < len(line):
        marker_start = cursor
        spaces = 0
        while (
            marker_start + spaces < len(line)
            and spaces < 3
            and line[marker_start + spaces] == " "
        ):
            spaces += 1
        probe = marker_start + spaces
        if probe < len(line) and line[probe] == ">":
            cursor = probe + 1
            if cursor < len(line) and line[cursor] in " \t":
                cursor += 1
            signature.append(_ContainerMarker("quote"))
            continue

        if (
            probe >= len(line)
            or line[probe] not in "-+*0123456789"
        ):
            break
        marker = re.match(
            r"(?:[-+*]|\d{1,9}[.)])",
            line[probe:],
        )
        if marker is None:
            break
        marker_end = probe + marker.end()
        if marker_end == len(line):
            cursor = marker_end
            signature.append(
                _ContainerMarker(
                    "list",
                    _column_width(
                        line[marker_start:marker_end]
                    )
                    + 1,
                )
            )
            continue
        if line[marker_end] not in " \t":
            break
        whitespace_end = marker_end
        while (
            whitespace_end < len(line)
            and line[whitespace_end] in " \t"
        ):
            whitespace_end += 1
        whitespace = line[marker_end:whitespace_end]
        columns = _whitespace_columns(whitespace)
        padding_end = (
            whitespace_end
            if columns <= 4
            else marker_end + 1
        )
        cursor = padding_end
        signature.append(
            _ContainerMarker(
                "list",
                _column_width(line[marker_start:padding_end]),
            )
        )
    return line[cursor:], cursor, tuple(signature)


def _continued_container_content(
    line: str,
    signature: Sequence[_ContainerMarker],
) -> tuple[str, int] | None:
    cursor = 0
    for marker in signature:
        if marker.kind == "quote":
            marker_start = cursor
            spaces = 0
            while (
                marker_start + spaces < len(line)
                and spaces < 3
                and line[marker_start + spaces] == " "
            ):
                spaces += 1
            probe = marker_start + spaces
            if probe >= len(line) or line[probe] != ">":
                return None
            cursor = probe + 1
            if cursor < len(line) and line[cursor] in " \t":
                cursor += 1
            continue
        if marker.kind != "list":
            return None
        if not line[cursor:].strip(" \t"):
            cursor = len(line)
            continue
        continued = _consume_indentation(
            line,
            cursor,
            marker.continuation_indent,
        )
        if continued is None:
            return None
        cursor = continued
    return line[cursor:], cursor


def _consume_indentation(
    line: str,
    start: int,
    minimum_columns: int,
) -> int | None:
    cursor = start
    columns = 0
    while (
        cursor < len(line)
        and line[cursor] in " \t"
        and columns < minimum_columns
    ):
        if line[cursor] == " ":
            columns += 1
        else:
            columns += 4 - (columns % 4)
        cursor += 1
    return cursor if columns >= minimum_columns else None


def _column_width(value: str) -> int:
    columns = 0
    for character in value:
        if character == "\t":
            columns += 4 - (columns % 4)
        else:
            columns += 1
    return columns


def _whitespace_columns(value: str) -> int:
    columns = 0
    for character in value:
        if character == " ":
            columns += 1
        elif character == "\t":
            columns += 4 - (columns % 4)
    return columns


def _fence_open(
    line: str,
) -> tuple[str, int, int, str] | None:
    match = FENCE_OPEN_PATTERN.match(line)
    if match is None:
        return None
    indent = len(match.group(1))
    marker_text = match.group(2)
    remainder = match.group(3)
    if marker_text[0] == "`" and "`" in remainder:
        return None
    info = remainder.strip(" \t")
    language = info.split(maxsplit=1)[0].lower() if info else ""
    return marker_text[0], len(marker_text), indent, language


def _is_fence_close(
    line: str,
    marker: str,
    minimum_length: int,
) -> bool:
    match = re.fullmatch(
        rf" {{0,3}}({re.escape(marker)}{{{minimum_length},}})[ \t]*",
        line,
    )
    return match is not None


def _strip_indent(line: str, maximum: int) -> str:
    removed = 0
    while removed < len(line) and removed < maximum and line[removed] == " ":
        removed += 1
    return line[removed:]


def _indent_columns(line: str) -> int:
    columns = 0
    for character in line:
        if character == " ":
            columns += 1
        elif character == "\t":
            columns += 4 - (columns % 4)
        else:
            break
        if columns >= 4:
            break
    return columns


def _mask_html_and_extract_links(
    text: str,
    block_mask: bytearray,
    line_starts: Sequence[int],
    line_context: _LineContext,
) -> tuple[
    bytearray,
    bytearray,
    list[Link],
    set[str],
    list[tuple[int, int]],
]:
    markdown_mask = bytearray(block_mask)
    heading_mask = bytearray(block_mask)
    raw_html_mask = bytearray(len(text))
    raw_html_ranges = _raw_html_block_ranges(text, block_mask)
    for block in raw_html_ranges:
        _mask_range(markdown_mask, block.start, block.end)
        _mask_range(heading_mask, block.start, block.end)
        raw_html_mask[block.start:block.end] = (
            b"\x01" * (block.end - block.start)
        )
    code_span_endings = _code_span_endings(
        text,
        block_mask,
        line_context,
    )
    links: list[Link] = []
    anchors: set[str] = set()
    angle_autolinks: list[tuple[int, int]] = []
    lowered = text.casefold()
    html_text = _container_prefix_masked_text(text)
    html_visible = bytearray(block_mask)
    inline_boundaries = [
        line_starts[index + 1]
        for index, boundary in enumerate(line_context.boundaries)
        if boundary and index + 1 < len(line_starts)
    ]
    for boundary in inline_boundaries:
        if boundary > 0:
            html_visible[boundary - 1] = 0
    escaped = _escape_flags(text)
    inline_html_closers = _inline_html_closer_index(text)
    raw_special_ends = {
        block.start: _raw_special_block_content_end(
            text,
            block,
            inline_html_closers,
        )
        for block in raw_html_ranges
        if block.block_type in {2, 3, 4, 5}
    }
    raw_stack: list[str] = []
    raw_stack_scope_end: int | None = None
    raw_range_index = 0
    cursor = 0

    while cursor < len(text):
        while (
            raw_range_index < len(raw_html_ranges)
            and cursor >= raw_html_ranges[raw_range_index].end
        ):
            raw_range_index += 1
        raw_block: _RawHtmlBlock | None = None
        if raw_range_index < len(raw_html_ranges):
            candidate_block = raw_html_ranges[raw_range_index]
            if candidate_block.start <= cursor < candidate_block.end:
                raw_block = candidate_block
        raw_block_end = raw_block.end if raw_block is not None else None
        if (
            raw_block is not None
            and raw_block.block_type in {2, 3, 4, 5}
            and cursor < raw_special_ends[raw_block.start]
        ):
            cursor = raw_special_ends[raw_block.start]
            continue
        if (
            raw_stack_scope_end is not None
            and cursor >= raw_stack_scope_end
        ):
            raw_stack.clear()
            raw_stack_scope_end = None
        if not block_mask[cursor]:
            cursor += 1
            continue
        raw_tag = raw_stack[-1] if raw_stack else None
        if raw_tag in {"script", "style", "textarea"}:
            closing = lowered.find(
                f"</{raw_tag}",
                cursor,
                raw_stack_scope_end or len(text),
            )
            if closing < 0:
                end = raw_stack_scope_end or len(text)
                _mask_range(markdown_mask, cursor, end)
                _mask_range(heading_mask, cursor, end)
                cursor = end
                raw_stack.clear()
                raw_stack_scope_end = None
                continue
            _mask_range(markdown_mask, cursor, closing)
            _mask_range(heading_mask, cursor, closing)
            cursor = closing
        elif raw_tag == "pre" and text[cursor] != "<":
            markdown_mask[cursor] = 0
            heading_mask[cursor] = 0
            cursor += 1
            continue

        code_span_end = code_span_endings.get(cursor)
        if (
            raw_tag is None
            and not raw_html_mask[cursor]
            and code_span_end is not None
        ):
            _mask_range(markdown_mask, cursor, code_span_end)
            cursor = code_span_end
            continue
        if text[cursor] != "<":
            cursor += 1
            continue
        if (
            raw_tag is None
            and not raw_html_mask[cursor]
            and escaped[cursor]
        ):
            cursor += 1
            continue

        boundary_index = bisect_right(inline_boundaries, cursor)
        scope_end = (
            inline_boundaries[boundary_index]
            if boundary_index < len(inline_boundaries)
            else len(text)
        )
        if raw_block is not None:
            scope_end = raw_block.end

        if raw_tag is None and not raw_html_mask[cursor]:
            autolink = ANGLE_AUTOLINK_CANDIDATE_PATTERN.match(
                text,
                cursor,
                scope_end,
            )
            if autolink is not None:
                candidate = autolink.group(1)
                if (
                    _is_uri_autolink(candidate)
                    or _is_standard_email_autolink(candidate)
                ):
                    end = autolink.end()
                    _mask_range(markdown_mask, cursor, end)
                    angle_autolinks.append((cursor, end))
                    cursor = end
                    continue

        special_end = _inline_raw_html_end(
            text,
            cursor,
            scope_end,
            inline_html_closers,
        )
        if special_end is not None:
            _mask_range(markdown_mask, cursor, special_end)
            _mask_range(heading_mask, cursor, special_end)
            cursor = special_end
            continue

        tag = _parse_html_tag(
            html_text,
            cursor,
            (
                block_mask
                if raw_block is not None
                else html_visible
            ),
            scope_end,
        )
        if tag is None:
            if raw_tag is not None:
                markdown_mask[cursor] = 0
                heading_mask[cursor] = 0
            cursor += 1
            continue
        _mask_range(markdown_mask, cursor, tag.end)
        _mask_range(heading_mask, cursor, tag.end)
        line_number = _line_number(line_starts, cursor)
        if not tag.closing and tag.name not in TAGFILTER_TAGS:
            for attribute in ("id", "name"):
                value = tag.attributes.get(attribute)
                if value:
                    anchors.add(unquote(html.unescape(value)))
            for attribute in ("href", "src"):
                target = tag.attributes.get(attribute)
                if target:
                    links.append(
                        Link(
                            target=html.unescape(target),
                            line=line_number,
                            navigable=(
                                tag.name == "a"
                                and attribute == "href"
                            ),
                        )
                    )
        if not tag.closing:
            if (
                tag.name in RAW_HTML_TAGS
                and tag.name not in TAGFILTER_TAGS
                and not tag.self_closing
            ):
                raw_stack.append(tag.name)
                if raw_block_end is not None:
                    raw_stack_scope_end = raw_block_end
        elif raw_stack and raw_stack[-1] == tag.name:
            raw_stack.pop()
            if not raw_stack:
                raw_stack_scope_end = None
        cursor = tag.end

    _restore_link_destinations(
        text,
        markdown_mask,
        block_mask,
    )
    return (
        markdown_mask,
        heading_mask,
        links,
        anchors,
        angle_autolinks,
    )


def _token_positions(text: str, token: str) -> array[int]:
    positions = array("I")
    cursor = 0
    while cursor < len(text):
        position = text.find(token, cursor)
        if position < 0:
            break
        positions.append(position)
        cursor = position + 1
    return positions


def _inline_html_closer_index(
    text: str,
) -> dict[str, array[int]]:
    return {
        token: _token_positions(text, token)
        for token in ("-->", "?>", "]]>", ">")
    }


def _indexed_token_find(
    text: str,
    token: str,
    start: int,
    end: int,
    positions: Mapping[str, Sequence[int]] | None,
) -> int:
    if positions is None:
        return text.find(token, start, end)
    candidates = positions[token]
    index = bisect_left(candidates, start)
    if index >= len(candidates) or candidates[index] >= end:
        return -1
    return candidates[index]


def _raw_special_block_content_end(
    text: str,
    block: _RawHtmlBlock,
    closer_positions: Mapping[str, Sequence[int]],
) -> int:
    token_by_type = {
        2: "-->",
        3: "?>",
        4: ">",
        5: "]]>",
    }
    token = token_by_type.get(block.block_type)
    if token is None:
        return block.start
    opening = text.find("<", block.start, block.end)
    if opening < 0:
        return block.end
    closing = _indexed_token_find(
        text,
        token,
        opening + 2,
        block.end,
        closer_positions,
    )
    if closing < 0:
        return block.end
    return min(block.end, closing + len(token))


def _inline_raw_html_end(
    text: str,
    start: int,
    scope_end: int,
    closer_positions: Mapping[str, Sequence[int]] | None = None,
) -> int | None:
    if text.startswith("<!--", start):
        if (
            text.startswith("<!-->", start)
            or text.startswith("<!--->", start)
        ):
            return None
        closing = _indexed_token_find(
            text,
            "-->",
            start + 4,
            scope_end,
            closer_positions,
        )
        if (
            closing < 0
            or (
                closing > start + 4
                and text[closing - 1] == "-"
            )
        ):
            return None
        return closing + 3
    if text.startswith("<?", start):
        closing = _indexed_token_find(
            text,
            "?>",
            start + 2,
            scope_end,
            closer_positions,
        )
        return None if closing < 0 else closing + 2
    if text.startswith("<![CDATA[", start):
        closing = _indexed_token_find(
            text,
            "]]>",
            start + 9,
            scope_end,
            closer_positions,
        )
        return None if closing < 0 else closing + 3
    if text.startswith("<!", start):
        declaration = INLINE_DECLARATION_START_PATTERN.match(
            text,
            start,
            scope_end,
        )
        if declaration is None:
            return None
        closing = _indexed_token_find(
            text,
            ">",
            declaration.end(),
            scope_end,
            closer_positions,
        )
        return None if closing < 0 else closing + 1
    return None


def _container_prefix_masked_text(text: str) -> str:
    if re.search(
        r"(?m)^ {0,3}(?:>|[-+*][ \t]|\d{1,9}[.)][ \t])",
        text,
    ) is None:
        return text
    parts: list[str] = []
    for raw_line in _markdown_splitlines(text, keepends=True):
        source = raw_line.rstrip("\r\n")
        _logical, prefix, _signature = _container_content(source)
        parts.append(" " * prefix + raw_line[prefix:])
    return "".join(parts)


def _unescaped_character_positions(
    text: str,
    character: str,
    escaped: bytearray | None = None,
) -> array[int]:
    escape_flags = escaped if escaped is not None else _escape_flags(text)
    return array(
        "I",
        (
            index
            for index, candidate in enumerate(text)
            if candidate == character and not escape_flags[index]
        ),
    )


def _indexed_position_before(
    positions: Sequence[int],
    start: int,
    end: int,
) -> int | None:
    index = bisect_left(positions, start)
    if index >= len(positions) or positions[index] >= end:
        return None
    return positions[index]


def _restore_link_destinations(
    text: str,
    markdown_mask: bytearray,
    block_mask: bytearray,
) -> None:
    escaped = _escape_flags(text)
    closing_parentheses = _unescaped_character_positions(
        text,
        ")",
        escaped,
    )
    cursor = 0
    while cursor < len(text):
        label_end = text.find("](", cursor)
        if label_end < 0:
            break
        opening = label_end + 1
        if (
            markdown_mask[label_end]
            and markdown_mask[opening]
            and block_mask[label_end]
            and block_mask[opening]
        ):
            limit = min(
                len(text),
                opening + MAX_INLINE_DESTINATION,
            )
            if (
                _indexed_position_before(
                    closing_parentheses,
                    opening + 1,
                    limit,
                )
                is None
            ):
                cursor = opening + 1
                continue
            destination = _inline_destination(
                text,
                opening,
                closing_parentheses,
            )
            if destination is not None:
                _target, destination_end = destination
                end = destination_end + 1
                if all(block_mask[opening:end]):
                    markdown_mask[opening:end] = b"\x01" * (
                        end - opening
                    )
                    cursor = end
                    continue
            closing = opening + 1
            paragraph_break = re.search(
                r"(?:\r\n|\r|\n)[ \t]*(?:\r\n|\r|\n)",
                text[opening:limit],
            )
            if paragraph_break is not None:
                limit = opening + paragraph_break.start()
            restored = False
            while closing < limit:
                if (
                    text[closing] == ")"
                    and not escaped[closing]
                ):
                    end = closing + 1
                    if all(block_mask[opening:end]):
                        markdown_mask[opening:end] = b"\x01" * (
                            end - opening
                        )
                        cursor = end
                        restored = True
                        break
                closing += 1
            if restored:
                continue
        cursor = opening + 1

    cursor = 0
    while cursor < len(text):
        opening = text.find("<", cursor)
        if opening < 0:
            return
        prefix = opening - 1
        while prefix >= 0 and text[prefix] in LINK_WHITESPACE:
            prefix -= 1
        whitespace = text[prefix + 1 : opening]
        candidate = (
            prefix >= 1
            and text[prefix] == ":"
            and text[prefix - 1] == "]"
            and markdown_mask[prefix]
            and markdown_mask[prefix - 1]
            and _valid_link_whitespace(whitespace)
        )
        if not candidate:
            cursor = opening + 1
            continue
        closing = opening + 1
        while closing < len(text):
            character = text[closing]
            if character in "\r\n" or character == "<":
                break
            if character == ">" and not escaped[closing]:
                end = closing + 1
                if all(block_mask[opening:end]):
                    markdown_mask[opening:end] = b"\x01" * (
                        end - opening
                    )
                cursor = end
                break
            closing += 1
        else:
            return
        if closing >= len(text) or text[closing] != ">":
            cursor = opening + 1


def _raw_html_block_ranges(
    text: str,
    block_mask: bytearray,
) -> list[_RawHtmlBlock]:
    ranges: list[_RawHtmlBlock] = []
    active_start: int | None = None
    active_signature: tuple[_ContainerMarker, ...] = ()
    active_kind: tuple[int, str | None] | None = None
    paragraph_open = False
    paragraph_signature: tuple[_ContainerMarker, ...] = ()
    definition_until = 0
    offset = 0
    raw_lines = _markdown_splitlines(text, keepends=True)
    definition_entries = [
        (
            *_container_content(raw_line.rstrip("\r\n")),
            raw_line.rstrip("\r\n"),
        )
        for raw_line in raw_lines
    ]
    for line_index, raw_line in enumerate(raw_lines):
        line_end = offset + len(raw_line)
        logical, prefix, signature, source = definition_entries[line_index]
        explicit_list_item = (
            prefix > 0
            and any(
                marker.kind == "list"
                for marker in signature
            )
        )
        if (
            not explicit_list_item
            and signature != paragraph_signature
            and any(
                marker.kind == "list"
                for marker in paragraph_signature
            )
        ):
            continued = _continued_container_content(
                source,
                paragraph_signature,
            )
            if continued is not None:
                logical, prefix = continued
                signature = paragraph_signature
        if signature != paragraph_signature:
            paragraph_open = False
            paragraph_signature = signature
        if active_start is not None:
            same_container = (
                signature == active_signature
                and not explicit_list_item
            )
            if not same_container:
                continued = (
                    None
                    if (
                        explicit_list_item
                        and signature == active_signature
                    )
                    else _continued_container_content(
                        source,
                        active_signature,
                    )
                )
                if continued is not None:
                    logical, _prefix = continued
                    signature = active_signature
                    same_container = True
            if not same_container:
                if active_kind is None:
                    raise AssertionError("active HTML block kind is missing")
                ranges.append(
                    _RawHtmlBlock(
                        active_start,
                        offset,
                        active_kind[0],
                        active_kind[1],
                    )
                )
                active_start = None
                active_signature = ()
                active_kind = None
                paragraph_open = False
            elif (
                active_kind is not None
                and active_kind[0] in {6, 7}
                and _is_markdown_blank(logical)
            ):
                ranges.append(
                    _RawHtmlBlock(
                        active_start,
                        offset,
                        active_kind[0],
                        active_kind[1],
                    )
                )
                active_start = None
                active_signature = ()
                active_kind = None
                paragraph_open = False
            else:
                if (
                    active_kind is not None
                    and _raw_html_block_ends(active_kind, logical)
                ):
                    ranges.append(
                        _RawHtmlBlock(
                            active_start,
                            line_end,
                            active_kind[0],
                            active_kind[1],
                        )
                    )
                    active_start = None
                    active_signature = ()
                    active_kind = None
                    paragraph_open = False
                offset = line_end
                continue
        if line_index < definition_until:
            paragraph_open = False
            offset = line_end
            continue
        if (
            not paragraph_open
            and _looks_like_reference_definition_start(logical)
        ):
            definition = _reference_definition_candidate(
                definition_entries,
                line_index,
            )
            if definition is not None:
                definition_until = line_index + definition[2]
                paragraph_open = False
                offset = line_end
                continue
        if (
            any(block_mask[offset:line_end])
            and (
                kind := _raw_html_block_kind(
                    logical,
                    allow_type_seven=not paragraph_open,
                )
            )
            is not None
        ):
            active_start = offset
            active_signature = signature
            active_kind = kind
            paragraph_open = False
            if _raw_html_block_ends(kind, logical):
                ranges.append(
                    _RawHtmlBlock(
                        active_start,
                        line_end,
                        kind[0],
                        kind[1],
                    )
                )
                active_start = None
                active_signature = ()
                active_kind = None
            offset = line_end
            continue
        if _is_markdown_blank(logical):
            paragraph_open = False
        elif SETEXT_HEADING_PATTERN.match(logical) and paragraph_open:
            paragraph_open = False
        elif _starts_block_line(logical):
            paragraph_open = False
        else:
            paragraph_open = True
        offset = line_end
    if active_start is not None:
        if active_kind is None:
            raise AssertionError("active HTML block kind is missing")
        ranges.append(
            _RawHtmlBlock(
                active_start,
                len(text),
                active_kind[0],
                active_kind[1],
            )
        )
    return ranges


def _starts_interrupting_raw_html_block(line: str) -> bool:
    return (
        _raw_html_block_kind(
            line,
            allow_type_seven=False,
        )
        is not None
    )


def _raw_html_block_kind(
    line: str,
    *,
    allow_type_seven: bool,
) -> tuple[int, str | None] | None:
    indent = len(line) - len(line.lstrip(" "))
    if indent > 3:
        return None
    candidate = line[indent:]
    if not candidate.startswith("<"):
        return None
    lowered = candidate.casefold()
    type_one = re.match(
        r"<(pre|script|style|textarea)(?:[ \t\v\f]|>|$)",
        lowered,
    )
    if type_one is not None:
        return 1, type_one.group(1)
    if candidate.startswith("<!--"):
        return 2, None
    if candidate.startswith("<?"):
        return 3, None
    if re.match(r"<![A-Za-z]", candidate):
        return 4, None
    if candidate.startswith("<![CDATA["):
        return 5, None
    type_six = re.match(
        r"</?([A-Za-z][A-Za-z0-9-]*)"
        r"(?:[ \t\v\f]|/?>|$)",
        candidate,
    )
    if (
        type_six is not None
        and type_six.group(1).casefold() in RAW_HTML_BLOCK_TAGS
    ):
        return 6, None
    if allow_type_seven and _is_complete_html_tag_line(candidate):
        return 7, None
    return None


def _raw_html_block_ends(
    kind: tuple[int, str | None],
    line: str,
) -> bool:
    block_type, tag_name = kind
    if block_type == 1:
        return (
            re.search(
                r"</(?:pre|script|style|textarea)>",
                line,
                re.IGNORECASE,
            )
            is not None
        )
    if block_type == 2:
        return (
            "-->" in line
            or "<!-->" in line
            or "<!--->" in line
        )
    if block_type == 3:
        return "?>" in line
    if block_type == 4:
        return ">" in line
    if block_type == 5:
        return "]]>" in line
    return False


def _is_complete_html_tag_line(line: str) -> bool:
    start = len(line) - len(line.lstrip(" "))
    visible = bytearray([1]) * len(line)
    tag = _parse_html_tag(line, start, visible)
    return bool(
        tag is not None
        and (tag.closing or tag.name not in RAW_HTML_TAGS)
        and not line[tag.end:].strip(" \t\f")
    )


def _parse_html_tag(
    text: str,
    start: int,
    visible: bytearray,
    limit: int | None = None,
) -> _HtmlTag | None:
    cursor = start + 1
    closing = False
    if cursor < len(text) and text[cursor] == "/":
        closing = True
        cursor += 1
    name_match = HTML_NAME_PATTERN.match(text, cursor)
    if name_match is None:
        return None
    name = name_match.group(0).casefold()
    cursor = name_match.end()
    attributes: dict[str, str] = {}
    self_closing = False
    maximum = min(
        len(text),
        start + 65536,
        limit if limit is not None else len(text),
    )

    while cursor < maximum:
        if not visible[cursor]:
            return None
        separator_start = cursor
        whitespace_end = _html_whitespace_end(
            text,
            cursor,
            maximum,
        )
        if whitespace_end is None:
            return None
        cursor = whitespace_end
        if cursor >= maximum:
            return None
        if text.startswith("/>", cursor):
            self_closing = True
            end = cursor + 2
            if not all(visible[start:end]):
                return None
            return _HtmlTag(
                name=name,
                attributes=attributes,
                closing=closing,
                self_closing=self_closing,
                end=end,
            )
        if text[cursor] == ">":
            end = cursor + 1
            if not all(visible[start:end]):
                return None
            return _HtmlTag(
                name=name,
                attributes=attributes,
                closing=closing,
                self_closing=self_closing,
                end=end,
            )
        if cursor == separator_start:
            return None
        if closing:
            return None
        attribute_match = HTML_ATTRIBUTE_NAME_PATTERN.match(text, cursor)
        if attribute_match is None:
            return None
        attribute = attribute_match.group(0).casefold()
        cursor = attribute_match.end()
        whitespace_end = _html_whitespace_end(
            text,
            cursor,
            maximum,
        )
        if whitespace_end is None:
            return None
        cursor = whitespace_end
        value = ""
        if cursor < maximum and text[cursor] == "=":
            cursor += 1
            whitespace_end = _html_whitespace_end(
                text,
                cursor,
                maximum,
            )
            if whitespace_end is None:
                return None
            cursor = whitespace_end
            if cursor >= maximum:
                return None
            quote = text[cursor] if text[cursor] in {'"', "'"} else None
            if quote is not None:
                cursor += 1
                value_start = cursor
                closing_quote = text.find(quote, cursor, maximum)
                if closing_quote < 0:
                    return None
                value = text[value_start:closing_quote]
                if re.search(
                    r"(?:\r\n|\r|\n)[ \t]*(?:\r\n|\r|\n)",
                    value,
                ):
                    return None
                cursor = closing_quote + 1
            else:
                value_start = cursor
                while (
                    cursor < maximum
                    and not text[cursor].isspace()
                    and text[cursor] not in {'"', "'", "=", "<", ">", "`"}
                ):
                    cursor += 1
                if cursor == value_start:
                    return None
                value = text[value_start:cursor]
        attributes.setdefault(attribute, value)
    return None


def _html_whitespace_end(
    text: str,
    start: int,
    maximum: int,
) -> int | None:
    cursor = start
    line_endings = 0
    while cursor < maximum:
        character = text[cursor]
        if character in " \t\f":
            cursor += 1
            continue
        if character == "\r":
            line_endings += 1
            cursor += 1
            if cursor < maximum and text[cursor] == "\n":
                cursor += 1
        elif character == "\n":
            line_endings += 1
            cursor += 1
        else:
            break
        if line_endings > 1:
            return None
    return cursor


def _code_span_endings(
    text: str,
    mask: bytearray,
    line_context: _LineContext | None = None,
) -> dict[int, int]:
    escaped = _escape_flags(text)
    runs: list[tuple[int, int, int, int]] = []
    cursor = 0
    segment = 0
    hidden = False
    context = line_context or _line_context(text)
    line_index = 0
    while cursor < len(text):
        character = text[cursor]
        if not mask[cursor]:
            if not hidden:
                segment += 1
                hidden = True
        else:
            hidden = False
        if character in "\r\n":
            if (
                line_index < len(context.boundaries)
                and context.boundaries[line_index]
            ):
                segment += 1
            line_index += 1
            cursor += 1
            if (
                character == "\r"
                and cursor < len(text)
                and text[cursor] == "\n"
            ):
                cursor += 1
            continue
        if not mask[cursor] or character != "`" or escaped[cursor]:
            cursor += 1
            continue
        end = cursor + 1
        while end < len(text) and mask[end] and text[end] == "`":
            end += 1
        runs.append((cursor, end, end - cursor, segment))
        cursor = end

    next_by_key: dict[tuple[int, int], int] = {}
    endings: dict[int, int] = {}
    for start, end, length, run_segment in reversed(runs):
        key = (run_segment, length)
        closing = next_by_key.get(key)
        if closing is not None:
            endings[start] = closing
        next_by_key[key] = end
    return endings


def _masked_text(text: str, mask: bytearray) -> str:
    return "".join(
        character
        if mask[index] or character in "\r\n"
        else " "
        for index, character in enumerate(text)
    )


def _heading_visible_text(text: str, mask: bytearray) -> str:
    return "".join(
        character
        for index, character in enumerate(text)
        if mask[index] or character in "\r\n"
    )


def _reference_definitions(text: str) -> dict[str, str]:
    return _reference_definition_data(text)[0]


def _reference_definition_data(
    text: str,
) -> tuple[dict[str, str], set[int]]:
    definitions: dict[str, str] = {}
    definition_lines: set[int] = set()
    source_lines = _markdown_splitlines(text)
    lines = [
        (*_container_content(source_line), source_line)
        for source_line in source_lines
    ]
    index = 0
    paragraph_open = False
    paragraph_signature: tuple[_ContainerMarker, ...] = ()
    while index < len(lines):
        line, prefix, signature, _source = lines[index]
        explicit_list_item = (
            prefix > 0
            and any(
                marker.kind == "list"
                for marker in signature
            )
        )
        if signature != paragraph_signature:
            lazy_definition_continuation = (
                paragraph_open
                and bool(paragraph_signature)
                and not explicit_list_item
                and _looks_like_reference_definition_start(line)
            )
            if not lazy_definition_continuation:
                paragraph_open = False
                paragraph_signature = signature
        elif explicit_list_item and paragraph_open:
            paragraph_open = False
        if _is_markdown_blank(line):
            paragraph_open = False
            index += 1
            continue
        if paragraph_open and SETEXT_HEADING_PATTERN.match(line):
            paragraph_open = False
            index += 1
            continue
        if paragraph_open:
            index += 1
            continue
        candidate = _reference_definition_candidate(lines, index)
        if candidate is not None:
            label, target, consumed = candidate
            definitions.setdefault(
                _reference_key(label),
                target,
            )
            definition_lines.update(
                range(index + 1, index + consumed + 1)
            )
            index += consumed
            continue
        if _starts_block_line(line):
            paragraph_open = False
        else:
            paragraph_open = True
        index += 1
    return definitions, definition_lines


def _reference_definition_candidate(
    lines: Sequence[
        tuple[str, int, tuple[_ContainerMarker, ...], str]
    ],
    start: int,
) -> tuple[str, str, int] | None:
    first, _prefix, signature, _source = lines[start]
    opening = len(first) - len(first.lstrip(" "))
    if (
        opening > 3
        or opening >= len(first)
        or first[opening] != "["
    ):
        return None

    label_parts: list[str] = []
    closing_line = start
    closing_column: int | None = None
    label_length = 0
    for line_index in range(start, len(lines)):
        if line_index == start:
            line = first
        else:
            line = _reference_content_in_container(
                lines[line_index],
                signature,
            )
        if line is None or _is_markdown_blank(line):
            return None
        cursor = opening + 1 if line_index == start else 0
        escaped = _escape_flags(line)
        while cursor < len(line):
            character = line[cursor]
            if not escaped[cursor] and character == "[":
                return None
            if not escaped[cursor] and character == "]":
                if (
                    cursor + 1 >= len(line)
                    or line[cursor + 1] != ":"
                ):
                    return None
                closing_line = line_index
                closing_column = cursor
                break
            label_parts.append(character)
            label_length += 1
            if label_length > 999:
                return None
            cursor += 1
        if closing_column is not None:
            break
        label_parts.append("\n")
        label_length += 1
        if label_length > 999:
            return None
    if closing_column is None:
        return None
    label = "".join(label_parts)
    if not label.strip(LINK_WHITESPACE):
        return None

    closing_content = (
        first
        if closing_line == start
        else _reference_content_in_container(
            lines[closing_line],
            signature,
        )
    )
    if closing_content is None:
        return None
    remainder = closing_content[closing_column + 2 :]
    destination_line = closing_line
    destination_source = remainder
    if not destination_source.strip(" \t"):
        destination_line += 1
        if destination_line >= len(lines):
            return None
        continuation = _reference_content_in_container(
            lines[destination_line],
            signature,
        )
        if (
            continuation is None
            or _is_markdown_blank(continuation)
            or _reference_line_starts_block(continuation)
        ):
            return None
        destination_source = continuation

    destination = _reference_destination_on_line(
        destination_source,
    )
    if destination is None:
        return None
    target, destination_end = destination
    definition_end = destination_line + 1
    tail = destination_source[destination_end:]
    whitespace_end = 0
    while (
        whitespace_end < len(tail)
        and tail[whitespace_end] in " \t"
    ):
        whitespace_end += 1
    title_source = tail[whitespace_end:]
    if title_source:
        if (
            whitespace_end == 0
            or title_source[0] not in {'"', "'", "("}
        ):
            return None
        title_end = _reference_title_end(
            lines,
            destination_line,
            destination_source,
            destination_end + whitespace_end,
            signature,
        )
        if title_end is None:
            return None
        definition_end = title_end
    elif definition_end < len(lines):
        optional_title_line = _reference_content_in_container(
            lines[definition_end],
            signature,
        )
        if (
            optional_title_line is not None
            and not _is_markdown_blank(optional_title_line)
            and not _reference_line_starts_block(optional_title_line)
        ):
            optional_start = len(optional_title_line) - len(
                optional_title_line.lstrip(" \t")
            )
            if (
                optional_start < len(optional_title_line)
                and optional_title_line[optional_start]
                in {'"', "'", "("}
            ):
                optional_end = _reference_title_end(
                    lines,
                    definition_end,
                    optional_title_line,
                    optional_start,
                    signature,
                )
                if optional_end is not None:
                    definition_end = optional_end

    return label, target, definition_end - start


def _reference_destination_on_line(
    line: str,
) -> tuple[str, int] | None:
    cursor = 0
    while cursor < len(line) and line[cursor] in " \t":
        cursor += 1
    start = cursor
    limit = min(len(line), start + MAX_INLINE_DESTINATION)
    if start >= len(line):
        return None
    if line[start] == "<":
        escaped = _escape_flags(line)
        cursor = start + 1
        while cursor < limit:
            character = line[cursor]
            if character == "<" and not escaped[cursor]:
                return None
            if character == ">" and not escaped[cursor]:
                target = line[start + 1 : cursor]
                return (
                    _unescape_markdown(html.unescape(target)),
                    cursor + 1,
                )
            cursor += 1
        return None

    depth = 0
    cursor = start
    while cursor < limit:
        character = line[cursor]
        if character in " \t":
            break
        if ord(character) < 0x20:
            return None
        if character == "\\":
            if (
                cursor + 1 < limit
                and line[cursor + 1] in MARKDOWN_ESCAPABLE
            ):
                cursor += 2
            else:
                cursor += 1
            continue
        if character == "(":
            depth += 1
            if depth > MAX_INLINE_PARENTHESIS_DEPTH:
                return None
        elif character == ")":
            if depth == 0:
                return None
            depth -= 1
        cursor += 1
    if cursor == start or depth != 0:
        return None
    target = line[start:cursor]
    return _unescape_markdown(html.unescape(target)), cursor


def _reference_title_end(
    lines: Sequence[
        tuple[str, int, tuple[_ContainerMarker, ...], str]
    ],
    line_index: int,
    first_line: str,
    opening: int,
    signature: tuple[_ContainerMarker, ...],
) -> int | None:
    opening_character = first_line[opening]
    closing_character = {
        '"': '"',
        "'": "'",
        "(": ")",
    }[opening_character]
    current_line = first_line
    cursor = opening + 1
    current_index = line_index
    while True:
        escaped = _escape_flags(current_line)
        while cursor < len(current_line):
            if (
                current_line[cursor] == closing_character
                and not escaped[cursor]
            ):
                if current_line[cursor + 1 :].strip(" \t"):
                    return None
                return current_index + 1
            cursor += 1
        current_index += 1
        if current_index >= len(lines):
            return None
        continuation = _reference_content_in_container(
            lines[current_index],
            signature,
        )
        if (
            continuation is None
            or _is_markdown_blank(continuation)
            or _reference_line_starts_block(continuation)
        ):
            return None
        current_line = continuation
        cursor = 0


def _reference_line_starts_block(line: str) -> bool:
    return bool(
        ATX_HEADING_PATTERN.match(line)
        or SETEXT_HEADING_PATTERN.match(line)
        or THEMATIC_BREAK_PATTERN.match(line)
        or EMPTY_LIST_PATTERN.match(line)
        or _fence_open(line) is not None
        or _starts_interrupting_raw_html_block(line)
        or _container_content(line)[2]
    )


def _reference_content_in_container(
    entry: tuple[str, int, tuple[_ContainerMarker, ...], str],
    signature: tuple[_ContainerMarker, ...],
) -> str | None:
    logical, prefix, parsed_signature, source = entry
    explicit_list_item = (
        prefix > 0
        and any(
            marker.kind == "list"
            for marker in parsed_signature
        )
    )
    if parsed_signature == signature and not explicit_list_item:
        return logical
    if any(marker.kind == "list" for marker in signature):
        continued = _continued_container_content(source, signature)
        if continued is not None:
            return continued[0]
    return None


def _looks_like_reference_definition_start(line: str) -> bool:
    stripped = line.lstrip(" ")
    return (
        len(line) - len(stripped) <= 3
        and stripped.startswith("[")
    )


def _starts_block_line(line: str) -> bool:
    return bool(
        ATX_HEADING_PATTERN.match(line)
        or THEMATIC_BREAK_PATTERN.match(line)
        or EMPTY_LIST_PATTERN.match(line)
        or _fence_open(line) is not None
        or _indent_columns(line) >= 4
    )


def _can_be_lazy_paragraph_continuation(line: str) -> bool:
    return bool(
        not _is_markdown_blank(line)
        and not _starts_block_line(line)
        and not _starts_interrupting_raw_html_block(line)
        and not _interrupting_list_marker(line)
    )


def _headings(
    text: str,
    definition_lines: set[int] | None = None,
) -> list[str]:
    headings: list[str] = []
    paragraph: list[str] = []
    paragraph_signature: tuple[_ContainerMarker, ...] | None = None
    open_list_signature: tuple[_ContainerMarker, ...] | None = None
    indented_code_signature: tuple[_ContainerMarker, ...] | None = None
    hidden_definitions = definition_lines or set()
    for line_number, source_line in enumerate(
        _markdown_splitlines(text),
        start=1,
    ):
        if line_number in hidden_definitions:
            paragraph = []
            paragraph_signature = None
            indented_code_signature = None
            continue
        line, prefix, signature = _container_content(source_line)
        continued = False
        lazy_continuation = False
        explicit_list_item = (
            prefix > 0
            and any(
                marker.kind == "list"
                for marker in signature
            )
        )
        continuation_signature = (
            paragraph_signature
            if (
                paragraph_signature is not None
                and any(
                    marker.kind == "list"
                    for marker in paragraph_signature
                )
            )
            else open_list_signature
        )
        if (
            not explicit_list_item
            and continuation_signature is not None
            and signature != continuation_signature
        ):
            continuation = _continued_container_content(
                source_line,
                continuation_signature,
            )
            if continuation is not None:
                line, prefix = continuation
                signature = continuation_signature
                continued = True
        if (
            not explicit_list_item
            and not continued
            and paragraph_signature is not None
            and signature != paragraph_signature
            and not signature
            and any(
                marker.kind == "quote"
                for marker in paragraph_signature
            )
            and _can_be_lazy_paragraph_continuation(source_line)
        ):
            line = source_line
            prefix = 0
            signature = paragraph_signature
            continued = True
            lazy_continuation = True

        if explicit_list_item:
            open_list_signature = signature
        elif (
            continued
            and any(marker.kind == "list" for marker in signature)
        ):
            open_list_signature = signature
        elif (
            signature
            and any(marker.kind == "list" for marker in signature)
        ):
            open_list_signature = signature
        elif not _is_markdown_blank(source_line):
            open_list_signature = None

        if indented_code_signature is not None:
            if (
                _is_markdown_blank(line)
                or (
                    signature == indented_code_signature
                    and _indent_columns(line) >= 4
                )
            ):
                continue
            indented_code_signature = None

        if (
            paragraph_signature is not None
            and (
                signature != paragraph_signature
                or (explicit_list_item and paragraph)
            )
        ):
            paragraph = []
            paragraph_signature = None

        if not paragraph and _indent_columns(line) >= 4:
            indented_code_signature = signature
            paragraph_signature = None
            continue

        atx = ATX_HEADING_PATTERN.match(line)
        if atx:
            content = atx.group(2) or ""
            content = re.sub(
                r"[ \t]+#+[ \t]*$",
                "",
                content,
            ).strip(" \t")
            if content:
                headings.append(content)
            paragraph = []
            paragraph_signature = None
            continue
        if (
            SETEXT_HEADING_PATTERN.match(line)
            and paragraph
            and paragraph_signature == signature
            and not lazy_continuation
        ):
            headings.append("\n".join(paragraph))
            paragraph = []
            paragraph_signature = None
            continue
        if (
            THEMATIC_BREAK_PATTERN.match(line)
            or EMPTY_LIST_PATTERN.match(line)
        ):
            paragraph = []
            paragraph_signature = None
            continue
        stripped = line.strip(" \t")
        if (
            not stripped
        ):
            paragraph = []
            paragraph_signature = None
        else:
            if paragraph_signature is None:
                paragraph_signature = signature
            paragraph.append(stripped)
    return headings


def _markdown_links(
    text: str,
    definitions: Mapping[str, str],
    line_context: _LineContext | None = None,
) -> list[tuple[str, bool, int]]:
    links, _syntaxes = _markdown_link_data(
        text,
        definitions,
        line_context,
    )
    return links


def _markdown_link_data(
    text: str,
    definitions: Mapping[str, str],
    line_context: _LineContext | None = None,
) -> tuple[
    list[tuple[str, bool, int]],
    list[_MarkdownLinkSyntax],
]:
    links: list[tuple[str, bool, int]] = []
    syntaxes: list[_MarkdownLinkSyntax] = []
    escaped = _escape_flags(text)
    closing_parentheses = _unescaped_character_positions(
        text,
        ")",
        escaped,
    )
    stack: list[dict[str, object]] = []
    last_nonimage_link = -1
    cursor = 0
    context = line_context or _line_context(text)
    line_index = 0
    while cursor < len(text):
        character = text[cursor]
        if character in "\r\n":
            next_start = cursor + 1
            if (
                character == "\r"
                and next_start < len(text)
                and text[next_start] == "\n"
            ):
                next_start += 1
            if (
                line_index < len(context.boundaries)
                and context.boundaries[line_index]
            ):
                stack.clear()
            line_index += 1
            cursor = next_start
            continue
        if character == "[" and not escaped[cursor]:
            image = (
                cursor > 0
                and text[cursor - 1] == "!"
                and not escaped[cursor - 1]
            )
            stack.append(
                {
                    "opening": cursor,
                    "image": image,
                    "links_start": len(links),
                }
            )
            cursor += 1
            continue
        if character != "]" or escaped[cursor] or not stack:
            cursor += 1
            continue
        frame = stack.pop()
        opening = int(frame["opening"])
        image = bool(frame["image"])
        links_start = int(frame["links_start"])
        child_link = last_nonimage_link > opening
        if image and len(links) > links_start:
            del links[links_start:]
            last_nonimage_link = max(
                (
                    position
                    for _target, navigable, position in links
                    if navigable
                ),
                default=-1,
            )
            child_link = False
        elif child_link:
            cursor += 1
            continue
        after = cursor + 1
        target: str | None = None
        consumed_until = after
        if after < len(text) and text[after] == "(":
            destination = _inline_destination(
                text,
                after,
                closing_parentheses,
            )
            if destination is not None:
                target, destination_end = destination
                consumed_until = destination_end + 1
            elif definitions and cursor - opening - 1 <= 999:
                label = text[opening + 1 : cursor]
                target = definitions.get(_reference_key(label))
        elif after < len(text) and text[after] == "[":
            reference_end = _reference_closing(text, after, escaped)
            if reference_end is not None:
                reference_length = reference_end - after - 1
                if reference_length == 0:
                    reference_start = opening + 1
                    reference_length = cursor - reference_start
                else:
                    reference_start = after + 1
                if reference_length <= 999:
                    reference = text[
                        reference_start:
                        reference_start + reference_length
                    ]
                    target = definitions.get(
                        _reference_key(reference)
                    )
                consumed_until = reference_end + 1
        elif definitions and cursor - opening - 1 <= 999:
            label = text[opening + 1 : cursor]
            target = definitions.get(_reference_key(label))

        if target is not None:
            syntaxes.append(
                _MarkdownLinkSyntax(
                    opening=opening,
                    label_end=cursor,
                    syntax_end=consumed_until,
                    image=image,
                )
            )
            links.append((target, not image, opening))
            if not image:
                last_nonimage_link = opening
        cursor = max(cursor + 1, consumed_until)
    return links, syntaxes


def _line_context(text: str) -> _LineContext:
    lines = tuple(_markdown_splitlines(text))
    table_lines = _gfm_table_line_indexes(lines)
    boundaries = tuple(
        (
            index in table_lines
            or _inline_stack_boundary(
                line,
                lines[index + 1]
                if index + 1 < len(lines)
                else "",
            )
        )
        for index, line in enumerate(lines)
    )
    return _LineContext(lines=lines, boundaries=boundaries)


def _gfm_table_line_indexes(
    lines: Sequence[str],
) -> set[int]:
    normalized: list[
        tuple[
            str,
            tuple[_ContainerMarker, ...],
            bool,
        ]
    ] = []
    active_signature: tuple[_ContainerMarker, ...] | None = None
    for source in lines:
        logical, prefix, signature = _container_content(source)
        explicit_list_item = (
            prefix > 0
            and any(marker.kind == "list" for marker in signature)
        )
        continued = False
        if (
            active_signature is not None
            and signature != active_signature
            and any(
                marker.kind == "list"
                for marker in active_signature
            )
        ):
            continuation = _continued_container_content(
                source,
                active_signature,
            )
            if continuation is not None:
                logical, _prefix = continuation
                signature = active_signature
                explicit_list_item = False
                continued = True
        normalized.append(
            (logical, signature, explicit_list_item)
        )
        if explicit_list_item:
            active_signature = signature
        elif continued or _is_markdown_blank(source):
            continue
        elif any(marker.kind == "list" for marker in signature):
            active_signature = signature
        else:
            active_signature = None

    table_lines: set[int] = set()
    for index in range(1, len(lines)):
        if "|" not in lines[index] or "-" not in lines[index]:
            continue
        separator, signature, separator_list_item = normalized[index]
        if _indent_columns(separator) >= 4:
            continue
        separator_cells = _gfm_table_cells(separator)
        if (
            separator_list_item
            or
            separator_cells is None
            or not separator_cells
            or not all(
                re.fullmatch(r":?-+:?", cell) is not None
                for cell in separator_cells
            )
        ):
            continue
        header, header_signature, _header_list_item = normalized[index - 1]
        if (
            _starts_block_line(header)
            or _starts_interrupting_raw_html_block(header)
        ):
            continue
        header_cells = _gfm_table_cells(header)
        if (
            signature != header_signature
            or header_cells is None
            or len(header_cells) != len(separator_cells)
        ):
            continue
        table_lines.update({index - 1, index})
        body_index = index + 1
        while body_index < len(lines):
            if "|" not in lines[body_index]:
                break
            body, body_signature, body_list_item = normalized[body_index]
            if (
                body_list_item
                or
                body_signature != signature
                or _is_markdown_blank(body)
                or not _contains_unescaped_pipe(body)
            ):
                break
            table_lines.add(body_index)
            body_index += 1
    return table_lines


def _inline_stack_boundary(
    current_line: str,
    next_line: str,
) -> bool:
    if _is_markdown_blank(current_line):
        return True
    current_probe = current_line.lstrip(" \t")[:1]
    next_probe = next_line.lstrip(" \t")[:1]
    boundary_markers = "#=-_*+>|<`~0123456789"
    if (
        current_probe
        and current_probe not in boundary_markers
        and (
            not next_probe
            or next_probe not in boundary_markers
        )
    ):
        return False
    if ATX_HEADING_PATTERN.match(current_line):
        return True
    if SETEXT_HEADING_PATTERN.match(current_line):
        return True
    if ATX_HEADING_PATTERN.match(next_line):
        return True
    if SETEXT_HEADING_PATTERN.match(next_line):
        return True
    (
        current_content,
        _current_prefix,
        current_signature,
    ) = _container_content(current_line)
    (
        next_content,
        next_prefix,
        next_signature,
    ) = _container_content(next_line)
    next_explicit_list_item = (
        next_prefix > 0
        and any(
            marker.kind == "list"
            for marker in next_signature
        )
    )
    if current_signature:
        continued = _continued_container_content(
            next_line,
            current_signature,
        )
        if continued is not None:
            next_content, _continued_prefix = continued
            next_signature = current_signature
        elif next_explicit_list_item:
            return True
        elif not next_signature:
            next_content = next_line
            next_signature = current_signature
    elif next_signature:
        if all(
            marker.kind == "list"
            for marker in next_signature
        ):
            return _interrupting_list_marker(next_line)
        return True
    if (
        THEMATIC_BREAK_PATTERN.match(current_content)
        or THEMATIC_BREAK_PATTERN.match(next_content)
        or _fence_open(current_content) is not None
        or _fence_open(next_content) is not None
        or _starts_interrupting_raw_html_block(current_content)
        or _starts_interrupting_raw_html_block(next_content)
    ):
        return True
    if next_signature != current_signature:
        return True
    return _interrupting_list_marker(next_content)


def _interrupting_list_marker(line: str) -> bool:
    match = re.match(
        r"^ {0,3}(?:(?P<bullet>[-+*])|"
        r"(?P<number>\d{1,9})[.)])[ \t]+",
        line,
    )
    if (
        match is None
        or _is_markdown_blank(line[match.end() :])
    ):
        return False
    return bool(
        match.group("bullet")
        or match.group("number") == "1"
    )


def _inline_destination(
    line: str,
    opening: int,
    closing_parentheses: Sequence[int] | None = None,
) -> tuple[str, int] | None:
    depth = 1
    cursor = opening + 1
    limit = min(len(line), opening + MAX_INLINE_DESTINATION)
    if (
        closing_parentheses is not None
        and _indexed_position_before(
            closing_parentheses,
            cursor,
            limit,
        )
        is None
    ):
        return None
    destination_started = False
    angle_destination = False
    while cursor < limit:
        character = line[cursor]
        if character == "\\":
            cursor += 2
            continue
        if not destination_started:
            if character in LINK_WHITESPACE:
                cursor += 1
                continue
            destination_started = True
            angle_destination = character == "<"
            if angle_destination:
                cursor += 1
                continue
        if angle_destination:
            if character in "\r\n" or character == "<":
                return None
            if character == ">":
                angle_destination = False
            cursor += 1
            continue
        if character == "(":
            depth += 1
            if depth > MAX_INLINE_PARENTHESIS_DEPTH:
                return None
        elif character == ")":
            depth -= 1
            if depth == 0:
                target = _link_destination(
                    line[opening + 1 : cursor],
                    allow_empty=True,
                )
                if target is not None:
                    return target, cursor
                depth = 1
        cursor += 1
    return None


def _reference_closing(
    line: str,
    opening: int,
    escaped: bytearray,
) -> int | None:
    limit = min(len(line), opening + 1001)
    cursor = opening + 1
    while cursor < limit:
        if line[cursor] == "]" and not escaped[cursor]:
            return cursor
        cursor += 1
    return None


def _link_destination(
    raw: str,
    *,
    allow_empty: bool = False,
) -> str | None:
    value = _strip_link_whitespace(raw)
    if value is None:
        return None
    if not value:
        return "" if allow_empty else None
    if value.startswith("<"):
        escaped = _escape_flags(value)
        closing = next(
            (
                index
                for index in range(1, len(value))
                if value[index] == ">" and not escaped[index]
            ),
            None,
        )
        if closing is None:
            return None
        target = value[1:closing]
        target_escaped = _escape_flags(target)
        if (
            "\n" in target
            or "\r" in target
            or any(
                character in "<>" and not target_escaped[index]
                for index, character in enumerate(target)
            )
        ):
            return None
        remainder = _link_title_remainder(value[closing + 1 :])
        if remainder is None:
            return None
    else:
        cursor = 0
        depth = 0
        while cursor < len(value):
            character = value[cursor]
            if character == "\\":
                if (
                    cursor + 1 < len(value)
                    and value[cursor + 1] in MARKDOWN_ESCAPABLE
                ):
                    cursor += 2
                else:
                    cursor += 1
                continue
            if character in LINK_WHITESPACE:
                if depth != 0:
                    return None
                break
            if ord(character) < 0x20:
                return None
            if character == "(":
                depth += 1
                if depth > MAX_INLINE_PARENTHESIS_DEPTH:
                    return None
            elif character == ")":
                if depth == 0:
                    return None
                depth -= 1
            cursor += 1
        if depth != 0 or cursor == 0:
            return None
        target = value[:cursor]
        remainder = _link_title_remainder(value[cursor:])
        if remainder is None:
            return None
    if remainder and not _valid_link_title(remainder):
        return None
    return _unescape_markdown(html.unescape(target))


def _strip_link_whitespace(value: str) -> str | None:
    start = 0
    while start < len(value) and value[start] in LINK_WHITESPACE:
        start += 1
    end = len(value)
    while end > start and value[end - 1] in LINK_WHITESPACE:
        end -= 1
    if not (
        _valid_link_whitespace(value[:start])
        and _valid_link_whitespace(value[end:])
    ):
        return None
    return value[start:end]


def _link_title_remainder(value: str) -> str | None:
    if not value:
        return ""
    separator_end = 0
    while (
        separator_end < len(value)
        and value[separator_end] in LINK_WHITESPACE
    ):
        separator_end += 1
    if (
        separator_end == 0
        or not _valid_link_whitespace(value[:separator_end])
    ):
        return None
    return value[separator_end:]


def _valid_link_whitespace(value: str) -> bool:
    line_endings = 0
    cursor = 0
    while cursor < len(value):
        character = value[cursor]
        if character not in LINK_WHITESPACE:
            return False
        if character == "\r":
            line_endings += 1
            if (
                cursor + 1 < len(value)
                and value[cursor + 1] == "\n"
            ):
                cursor += 1
        elif character == "\n":
            line_endings += 1
        if line_endings > 1:
            return False
        cursor += 1
    return True


def _valid_link_title(value: str) -> bool:
    if len(value) < 2:
        return False
    opening = value[0]
    closing = {
        '"': '"',
        "'": "'",
        "(": ")",
    }.get(opening)
    if closing is None or value[-1] != closing:
        return False
    if re.search(r"(?:\r\n|\r|\n)[ \t]*(?:\r\n|\r|\n)", value):
        return False
    escaped = _escape_flags(value)
    return not any(
        character == closing and not escaped[index]
        for index, character in enumerate(value[1:-1], start=1)
    )


def _exact_markdown_link_label(
    value: str,
    definitions: Mapping[str, str],
) -> str | None:
    text = value.strip(LINK_WHITESPACE)
    if not text.startswith("[") or text.startswith("!["):
        return None
    line_context = _line_context(text)
    block_mask, _fences, _unclosed = _block_mask_and_fences(text)
    (
        markdown_mask,
        _heading_mask,
        _html_links,
        _anchors,
        _angle_autolinks,
    ) = (
        _mask_html_and_extract_links(
            text,
            block_mask,
            _line_starts(text),
            line_context,
        )
    )
    visible = _masked_text(text, markdown_mask)
    parsed_links = [
        (target, opening)
        for target, navigable, opening in _markdown_links(
            visible,
            definitions,
            line_context,
        )
        if navigable
    ]
    if len(parsed_links) != 1 or parsed_links[0][1] != 0:
        return None
    escaped = _escape_flags(visible)
    depth = 0
    closing = None
    for index, character in enumerate(visible):
        if escaped[index]:
            continue
        if character == "[":
            depth += 1
        elif character == "]":
            depth -= 1
            if depth == 0:
                closing = index
                break
            if depth < 0:
                return None
    exact = False
    if closing is None or closing + 1 >= len(visible):
        exact = (
            closing == len(visible) - 1
            and _reference_key(visible[1:closing]) in definitions
        )
    elif visible[closing + 1] == "(":
        destination = _inline_destination(visible, closing + 1)
        exact = (
            destination is not None
            and destination[1] == len(visible) - 1
        )
    elif visible[closing + 1] == "[" and visible.endswith("]"):
        reference = (
            visible[closing + 2 : -1]
            or visible[1:closing]
        )
        exact = _reference_key(reference) in definitions
    if not exact or closing is None:
        return None
    return text[1:closing]


def _unescape_markdown(value: str) -> str:
    result: list[str] = []
    cursor = 0
    while cursor < len(value):
        if (
            value[cursor] == "\\"
            and cursor + 1 < len(value)
            and value[cursor + 1] in MARKDOWN_ESCAPABLE
        ):
            result.append(value[cursor + 1])
            cursor += 2
        else:
            result.append(value[cursor])
            cursor += 1
    return "".join(result)


def _escape_flags(text: str) -> bytearray:
    flags = bytearray(len(text))
    backslashes = 0
    for index, character in enumerate(text):
        if character == "\\":
            backslashes += 1
            continue
        if backslashes % 2:
            flags[index] = 1
        backslashes = 0
    return flags


def _line_starts(text: str) -> list[int]:
    starts = [0]
    cursor = 0
    while cursor < len(text):
        if text[cursor] == "\r":
            cursor += 1
            if cursor < len(text) and text[cursor] == "\n":
                cursor += 1
            starts.append(cursor)
            continue
        if text[cursor] == "\n":
            cursor += 1
            starts.append(cursor)
            continue
        cursor += 1
    return starts


def _line_number(starts: Sequence[int], position: int) -> int:
    return bisect_right(starts, position)


def _mask_range(mask: bytearray, start: int, end: int) -> None:
    mask[start:end] = b"\x00" * (end - start)


def _paragraph_count(lines: Sequence[str]) -> int:
    count = 0
    inside = False
    for line in lines:
        if not _is_markdown_blank(line):
            if not inside:
                count += 1
                inside = True
        else:
            inside = False
    return count


def _is_single_visible_paragraph(lines: Sequence[str]) -> bool:
    text = "\n".join(lines)
    block_mask, fences, unclosed = _block_mask_and_fences(text)
    if fences or unclosed is not None:
        return False
    raw_blocks = _raw_html_block_ranges(text, block_mask)
    if any(block.block_type not in {2, 3, 4, 5} for block in raw_blocks):
        return False
    paragraph_mask = bytearray(b"\x01") * len(text)
    for block in raw_blocks:
        _mask_range(paragraph_mask, block.start, block.end)
    visible_lines = _markdown_splitlines(
        _masked_text(text, paragraph_mask)
    )
    _definitions, definition_lines = _reference_definition_data(
        "\n".join(visible_lines)
    )
    visible_lines = [
        (
            ""
            if line_number in definition_lines
            else line
        )
        for line_number, line in enumerate(
            visible_lines,
            start=1,
        )
    ]
    if _paragraph_count(visible_lines) != 1:
        return False
    paragraph_open = False
    for line in visible_lines:
        if _is_markdown_blank(line):
            paragraph_open = False
            continue
        logical, _prefix, signature = _container_content(line)
        if signature:
            lazy_list_continuation = (
                paragraph_open
                and all(
                    marker.kind == "list"
                    for marker in signature
                )
                and not _interrupting_list_marker(line)
            )
            if not lazy_list_continuation:
                return False
            logical = line
        if SETEXT_HEADING_PATTERN.match(logical) and paragraph_open:
            return False
        if (
            (
                not paragraph_open
                and (
                    _indent_columns(logical) >= 4
                    or EMPTY_LIST_PATTERN.match(logical)
                )
            )
            or ATX_HEADING_PATTERN.match(logical)
            or THEMATIC_BREAK_PATTERN.match(logical)
            or _fence_open(logical) is not None
            or _starts_interrupting_raw_html_block(logical)
        ):
            return False
        paragraph_open = True
    return not _contains_visible_gfm_table(text)


def _reference_key(value: str) -> str:
    return " ".join(value.casefold().split())


def _heading_anchors(
    headings: Sequence[str],
    definitions: Mapping[str, str],
) -> set[str]:
    anchors: set[str] = set()
    next_suffix: dict[str, int] = {}
    for heading in headings:
        base = _github_slug(heading, definitions)
        if not base:
            continue
        anchor = base
        suffix = next_suffix.get(base, 1)
        while anchor in anchors:
            anchor = f"{base}-{suffix}"
            suffix += 1
        next_suffix[base] = suffix
        anchors.add(anchor)
    return anchors


def _github_slug(
    value: str,
    definitions: Mapping[str, str] | None = None,
) -> str:
    code_underscore = "\ue000"
    code_ampersand = "\ue001"
    text = _heading_link_text(value, definitions or {})
    text = _heading_code_text(
        text,
        code_underscore,
        code_ampersand,
    )
    text = _unescape_markdown(text)
    text = html.unescape(text)
    text = re.sub(
        r"(?<!\w)_+(?=\w)|(?<=\w)_+(?!\w)",
        "",
        text,
    )
    text = re.sub(r"[`*~]", "", text).lower()
    text = text.replace(code_underscore, "_")
    text = "".join(
        (
            "-"
            if character == " "
            else character
        )
        for character in text
        if (
            unicodedata.category(character)[:1] in {"L", "M", "N"}
            or character == " "
            or character in {"-", "_"}
        )
    )
    return text


def _heading_link_text(
    value: str,
    definitions: Mapping[str, str],
) -> str:
    code_mask = bytearray(b"\x01") * len(value)
    for opening, ending in _code_span_endings(
        value,
        code_mask,
        _line_context(value),
    ).items():
        _mask_range(code_mask, opening, ending)
    link_probe = _masked_text(value, code_mask)
    _links, syntaxes = _markdown_link_data(
        link_probe,
        definitions,
        _line_context(link_probe),
    )
    if not syntaxes:
        return value

    removed = bytearray(len(value))
    for syntax in syntaxes:
        if syntax.image and syntax.opening > 0:
            removed[syntax.opening - 1] = 1
        removed[syntax.opening] = 1
        removed[syntax.label_end] = 1
        suffix_start = syntax.label_end + 1
        removed[suffix_start:syntax.syntax_end] = (
            b"\x01" * (syntax.syntax_end - suffix_start)
        )
    return "".join(
        character
        for index, character in enumerate(value)
        if not removed[index]
    )


def _heading_code_text(
    value: str,
    underscore_marker: str,
    ampersand_marker: str,
) -> str:
    mask = bytearray(b"\x01") * len(value)
    endings = _code_span_endings(value, mask)
    result: list[str] = []
    cursor = 0
    while cursor < len(value):
        ending = endings.get(cursor)
        if ending is None:
            result.append(value[cursor])
            cursor += 1
            continue
        marker_length = 1
        while (
            cursor + marker_length < len(value)
            and value[cursor + marker_length] == "`"
        ):
            marker_length += 1
        content = value[
            cursor + marker_length:
            ending - marker_length
        ].replace("\r\n", "\n").replace("\r", "\n")
        content = content.replace("\n", " ")
        if (
            len(content) >= 2
            and content.startswith(" ")
            and content.endswith(" ")
            and content.strip(" ")
        ):
            content = content[1:-1]
        result.extend(
            (
                underscore_marker
                if character == "_"
                else (
                    ampersand_marker
                    if character == "&"
                    else character
                )
            )
            for character in content
            if (
                unicodedata.category(character)[:1]
                in {"L", "M", "N"}
                or character in {" ", "-", "_", "&"}
            )
        )
        cursor = ending
    return "".join(result)


def _route_state_members(
    route_class: ast.ClassDef,
) -> dict[str, str]:
    if (
        route_class.decorator_list
        or route_class.keywords
        or getattr(route_class, "type_params", ())
        or len(route_class.bases) != 1
        or not isinstance(route_class.bases[0], ast.Name)
        or route_class.bases[0].id != "StrEnum"
    ):
        raise ValueError("RouteState должен напрямую наследовать StrEnum")
    members: dict[str, str] = {}
    for statement in route_class.body:
        assignment = _simple_assignment(statement)
        if (
            not isinstance(statement, ast.Assign)
            or assignment is None
            or not STATE_NAME_PATTERN.fullmatch(assignment[0])
        ):
            raise ValueError(
                "RouteState допускает только UPPER_SNAKE строковые состояния"
            )
        name, value = assignment
        if not (
            isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and value.value == name
        ):
            raise ValueError(
                "значение RouteState должно дословно совпадать с именем"
            )
        if name in members or value.value in members.values():
            raise ValueError("RouteState содержит повторяющееся значение")
        members[name] = value.value
    if not members:
        raise ValueError("RouteState не содержит строковых состояний")
    return members


def _is_transition_annotation(annotation: ast.expr) -> bool:
    if not (
        isinstance(annotation, ast.Subscript)
        and isinstance(annotation.value, ast.Name)
        and annotation.value.id == "dict"
        and isinstance(annotation.slice, ast.Tuple)
        and len(annotation.slice.elts) == 2
    ):
        return False
    before, after = annotation.slice.elts
    return (
        isinstance(before, ast.Name)
        and before.id == "RouteState"
        and isinstance(after, ast.Subscript)
        and isinstance(after.value, ast.Name)
        and after.value.id == "frozenset"
        and isinstance(after.slice, ast.Name)
        and after.slice.id == "RouteState"
    )


def _simple_assignment(
    statement: ast.stmt,
) -> tuple[str, ast.expr] | None:
    if (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
    ):
        return statement.targets[0].id, statement.value
    if (
        isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
        and statement.value is not None
    ):
        return statement.target.id, statement.value
    return None


def _state_set(
    expression: ast.expr,
    members: Mapping[str, str],
) -> set[str]:
    items = _frozenset_items(expression)
    values = [
        _state_reference(item, members)
        for item in items
    ]
    if len(values) != len(set(values)):
        raise ValueError("frozenset повторяет состояние")
    return set(values)


def _transition_pairs(
    expression: ast.expr,
    members: Mapping[str, str],
    terminals: set[str],
) -> tuple[set[tuple[str, str]], set[str]]:
    if not isinstance(expression, ast.Dict):
        raise ValueError("ALLOWED_TRANSITIONS должен быть словарём")
    pairs: set[tuple[str, str]] = set()
    before_states: set[str] = set()
    expansion_count = 0
    entries = list(
        zip(
            expression.keys,
            expression.values,
            strict=True,
        )
    )
    for index, (key, value) in enumerate(
        entries,
    ):
        if key is None:
            _validate_terminal_expansion(value)
            expansion_count += 1
            if index != len(entries) - 1:
                raise ValueError(
                    "раскрытие TERMINAL_STATES должно быть последним"
                )
            continue
        before = _state_reference(key, members)
        if before in before_states:
            raise ValueError(
                f"ALLOWED_TRANSITIONS повторяет состояние {before}"
            )
        if before in terminals:
            raise ValueError(
                "терминальные состояния задаются только раскрытием"
            )
        before_states.add(before)
        after_states = [
            _state_reference(item, members)
            for item in _frozenset_items(value)
        ]
        if len(after_states) != len(set(after_states)):
            raise ValueError(
                f"переходы из {before} повторяют состояние"
            )
        for after in after_states:
            pairs.add((before, after))
    if expansion_count != 1:
        raise ValueError(
            "ожидалось ровно одно раскрытие TERMINAL_STATES"
        )
    return pairs, before_states | terminals


def _frozenset_items(expression: ast.expr) -> Sequence[ast.expr]:
    if not (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Name)
        and expression.func.id == "frozenset"
        and not expression.keywords
    ):
        raise ValueError("ожидался явный frozenset")
    if not expression.args:
        return ()
    if len(expression.args) != 1 or not isinstance(
        expression.args[0],
        ast.Set,
    ):
        raise ValueError("frozenset должен содержать явный набор состояний")
    return expression.args[0].elts


def _state_reference(
    expression: ast.expr,
    members: Mapping[str, str],
) -> str:
    if not (
        isinstance(expression, ast.Attribute)
        and isinstance(expression.value, ast.Name)
        and expression.value.id == "RouteState"
        and expression.attr in members
    ):
        raise ValueError("ожидалась ссылка RouteState.<STATE>")
    return members[expression.attr]


def _validate_terminal_expansion(expression: ast.expr) -> None:
    if not isinstance(expression, ast.DictComp):
        raise ValueError(
            "раскрытие терминальных состояний имеет неизвестный вид"
        )
    if (
        len(expression.generators) != 1
        or not isinstance(expression.key, ast.Name)
        or not isinstance(expression.generators[0].target, ast.Name)
        or expression.key.id != "state"
        or expression.generators[0].target.id != "state"
        or expression.key.id != expression.generators[0].target.id
        or not isinstance(expression.generators[0].iter, ast.Name)
        or expression.generators[0].iter.id != "TERMINAL_STATES"
        or expression.generators[0].ifs
        or expression.generators[0].is_async
        or _frozenset_items(expression.value)
    ):
        raise ValueError(
            "раскрытие TERMINAL_STATES имеет неизвестный вид"
        )
