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
from .generic_parser import GenericLogParser
from .jsonlines_parser import JsonLinesParser
from .syslog_parser import SyslogParser
from .zeek_parser import ZeekParser

# Priority order: most specific first, ending with universal fallback GenericLogParser
_PARSER_CLASSES: list[type[BaseParser]] = [
    FortigateParser,
    AuditdParser,
    JsonLinesParser,
    ZeekParser,
    SyslogParser,
    CsvParser,
    GenericLogParser,
]


def get_parser(sample_lines: list[str]) -> BaseParser:
    """
    Test sample lines against each parser in priority order.
    Returns an instance of the first parser that matches.
    If no specialized format matches, returns GenericLogParser to guarantee 100% ingest success.
    """
    for parser_cls in _PARSER_CLASSES:
        parser = parser_cls()
        if parser.can_parse(sample_lines):
            return parser
    return GenericLogParser()


def get_format_name(parser: BaseParser) -> str:
    """Return a human-readable format name for a parser instance."""
    name_map = {
        FortigateParser: "fortigate",
        AuditdParser: "auditd",
        JsonLinesParser: "jsonlines",
        ZeekParser: "zeek",
        SyslogParser: "syslog",
        CsvParser: "csv",
        GenericLogParser: "generic_log",
    }
    return name_map.get(type(parser), "generic_log")


def get_parser_by_name(format_name: str) -> BaseParser:
    """Return an instance of a parser given its format name, defaulting to GenericLogParser."""
    name_to_class = {
        "fortigate": FortigateParser,
        "auditd": AuditdParser,
        "jsonlines": JsonLinesParser,
        "zeek": ZeekParser,
        "syslog": SyslogParser,
        "csv": CsvParser,
        "generic_log": GenericLogParser,
    }
    cls = name_to_class.get(format_name.lower())
    return cls() if cls else GenericLogParser()


__all__ = [
    "AuditdParser",
    "BaseParser",
    "CsvParser",
    "FortigateParser",
    "GenericLogParser",
    "JsonLinesParser",
    "SyslogParser",
    "ZeekParser",
    "get_format_name",
    "get_parser",
    "get_parser_by_name",
]
