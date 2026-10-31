"""
Parser registry — auto-discovers and selects the right parser for a given log sample.

WHY: The ingest pipeline calls get_parser(sample_lines) once per dataset. The registry
tests each parser in priority order and returns the first match. Adding a new format
requires only creating a new parser file — no changes to this registry or the pipeline.
"""
from __future__ import annotations

from .auditd_parser import AuditdParser
from .base import BaseParser
from .csv_parser import CsvParser
from .fortigate_parser import FortigateParser
from .jsonlines_parser import JsonLinesParser
from .syslog_parser import SyslogParser

# Priority order: most specific first
_PARSER_CLASSES: list[type[BaseParser]] = [
    FortigateParser,
    AuditdParser,
    JsonLinesParser,
    SyslogParser,
    CsvParser,
]


def get_parser(sample_lines: list[str]) -> BaseParser | None:
    """
    Test sample lines against each parser in priority order.
    Returns an instance of the first parser that matches, or None if no match.
    """
    for parser_cls in _PARSER_CLASSES:
        parser = parser_cls()
        if parser.can_parse(sample_lines):
            return parser
    return None


def get_format_name(parser: BaseParser) -> str:
    """Return a human-readable format name for a parser instance."""
    name_map = {
        FortigateParser: "fortigate",
        AuditdParser: "auditd",
        JsonLinesParser: "jsonlines",
        SyslogParser: "syslog",
        CsvParser: "csv",
    }
    return name_map.get(type(parser), "unknown")


def get_parser_by_name(format_name: str) -> BaseParser | None:
    """Return an instance of a parser given its format name."""
    name_to_class = {
        "fortigate": FortigateParser,
        "auditd": AuditdParser,
        "jsonlines": JsonLinesParser,
        "syslog": SyslogParser,
        "csv": CsvParser,
    }
    cls = name_to_class.get(format_name.lower())
    return cls() if cls else None


__all__ = [
    "AuditdParser",
    "BaseParser",
    "CsvParser",
    "FortigateParser",
    "JsonLinesParser",
    "SyslogParser",
    "get_format_name",
    "get_parser",
]
