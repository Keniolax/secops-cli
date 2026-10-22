"""One result type for every subcommand, printed as text or JSON.

Text is for people. JSON is for other programs: a SIEM, jq, a CI job. Keeping
both in one Report means the two modes can never disagree about the facts.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Any, TextIO

# Exit codes. Schedulers and CI read these, not the text.
OK = 0  # ran, found nothing that needs attention
FINDINGS = 1  # ran, found something: changed files, a brute force, a cert near expiry
ERROR = 2  # could not run: bad input, out of scope, unreadable file


@dataclass
class Report:
    data: dict[str, Any]
    lines: list[str] = field(default_factory=list)
    exit_code: int = OK


def emit(report: Report, as_json: bool, stream: TextIO | None = None) -> None:
    stream = stream or sys.stdout
    if as_json:
        json.dump(report.data, stream, indent=2, sort_keys=True, default=str)
        stream.write("\n")
    else:
        for line in report.lines:
            stream.write(line + "\n")
    stream.flush()
