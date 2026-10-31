"""
Profiler service — fast format detection and metadata sampling.

WHY: Before ingesting a 15-50 GB file, we need to know its format, delimiter,
timestamp field, and approximate event count — WITHOUT loading it into memory.
The profiler reads only 3 small byte slices (head, middle, tail) to answer all
these questions in < 1 second on any file size.

ENGINEERING PRINCIPLE: Fail-fast — if the profiler can't identify the format,
the dataset is rejected immediately with a clear error, not halfway through
a 2-hour ingest.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..connectors.parsers import get_format_name, get_parser
from ..connectors.parsers.base import BaseParser


@dataclass
class ProfileResult:
    """Results from profiling a raw log file."""

    format_name: str  # "auditd", "jsonlines", "syslog", "csv", "unknown"
    parser: BaseParser | None  # Ready-to-use parser instance
    file_path: str  # Absolute path
    size_bytes: int  # File size
    estimated_lines: int  # Rough line count estimate
    sample_head: list[str]  # First N lines
    sample_tail: list[str]  # Last N lines
    hosts_sample: list[str]  # Unique hosts found in samples
    time_range_hint: tuple | None  # (earliest_ts, latest_ts) from samples


def profile_file(file_path: str | Path, sample_size: int = 50) -> ProfileResult:
    """
    Profile a single log file by reading small byte slices from head, middle, and tail.

    HOW IT STAYS UNDER 8 GB RAM:
    - Reads at most 3 × 64 KB chunks (total ~192 KB) regardless of file size.
    - Never loads the entire file. Never iterates all lines.
    - Estimates total line count from average line length in the sample.

    Args:
        file_path: Path to the raw log file.
        sample_size: Max lines to sample from each slice.

    Returns:
        ProfileResult with format, parser, size, and metadata estimates.
    """
    fpath = Path(file_path).resolve()
    size_bytes = fpath.stat().st_size
    chunk_bytes = 64 * 1024  # 64 KB per slice — enough for ~50-200 lines

    # --- Read head, middle, tail byte slices ---
    head_lines = _read_chunk_lines(fpath, offset=0, chunk_bytes=chunk_bytes, max_lines=sample_size)

    mid_offset = max(0, size_bytes // 2 - chunk_bytes // 2)
    mid_lines = _read_chunk_lines(fpath, offset=mid_offset, chunk_bytes=chunk_bytes, max_lines=sample_size)

    tail_offset = max(0, size_bytes - chunk_bytes)
    tail_lines = _read_chunk_lines(fpath, offset=tail_offset, chunk_bytes=chunk_bytes, max_lines=sample_size)

    all_sample_lines = head_lines + mid_lines + tail_lines

    # --- Detect format ---
    parser = get_parser(all_sample_lines)
    format_name = get_format_name(parser) if parser else "unknown"

    # --- Estimate total lines ---
    non_blank = [line_item for line_item in all_sample_lines if line_item.strip()]
    avg_line_bytes = sum(len(line_item.encode("utf-8", errors="replace")) for line_item in non_blank) / max(
        len(non_blank), 1
    )
    estimated_lines = int(size_bytes / max(avg_line_bytes, 1)) if avg_line_bytes > 0 else 0

    # --- Extract hosts and time range from sample ---
    hosts_sample: list[str] = []
    earliest_ts = None
    latest_ts = None

    if parser:
        for line in non_blank[:100]:
            parsed = parser.parse_line(line)
            if parsed:
                h = parsed.get("host")
                if h and h not in hosts_sample:
                    hosts_sample.append(h)
                ts = parsed.get("timestamp")
                if ts:
                    if earliest_ts is None or ts < earliest_ts:
                        earliest_ts = ts
                    if latest_ts is None or ts > latest_ts:
                        latest_ts = ts

    time_range_hint = (earliest_ts, latest_ts) if earliest_ts and latest_ts else None

    return ProfileResult(
        format_name=format_name,
        parser=parser,
        file_path=str(fpath),
        size_bytes=size_bytes,
        estimated_lines=estimated_lines,
        sample_head=head_lines[:10],
        sample_tail=tail_lines[-10:],
        hosts_sample=hosts_sample,
        time_range_hint=time_range_hint,
    )


def _read_chunk_lines(fpath: Path, offset: int, chunk_bytes: int, max_lines: int) -> list[str]:
    """
    Read a byte chunk from the file and split into lines.
    Discards the first partial line (if offset > 0) and last partial line.
    """
    try:
        with open(fpath, "rb") as f:
            f.seek(offset)
            chunk = f.read(chunk_bytes)
    except OSError:
        return []

    text = chunk.decode("utf-8", errors="replace")
    lines = text.split("\n")

    # If we seeked into the middle of the file, the first "line" is partial — drop it
    if offset > 0 and lines:
        lines = lines[1:]

    # The last line may be partial — drop it unless it's the end of file
    if lines and not text.endswith("\n"):
        lines = lines[:-1]

    # Strip and limit
    return [line_item for line_item in lines if line_item.strip()][:max_lines]
