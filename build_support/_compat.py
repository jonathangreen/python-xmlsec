"""distutils replacements for Python 3.12+.

``distutils`` was deprecated in 3.10 and removed in 3.12. Older code in
``build_support`` referenced ``distutils.errors.DistutilsError``,
``distutils.log``, and ``distutils.version.StrictVersion``. This module
provides minimal stand-ins so the build code keeps working under modern
Python without pulling in the removed package.
"""

from __future__ import annotations

import logging
from typing import Iterable


class BuildError(Exception):
    """Stand-in for the removed ``distutils.errors.DistutilsError``."""


# Mimic the bits of the ``distutils.log`` API we actually used: a module-level
# ``info`` callable and an ``INFO`` level constant. Backed by stdlib logging so
# the messages still surface through the usual handlers.
log = logging.getLogger('build_support')
log.INFO = logging.INFO  # type: ignore[attr-defined]


def parse_version(text: str) -> tuple[int, ...]:
    """Parse a dotted-int version string into a sortable tuple.

    Used in place of ``distutils.version.StrictVersion`` for sorting release
    download links (e.g. ``"1.18"``, ``"2.14.6"``). Non-integer parts collapse
    to ``0`` so the comparison is total without requiring strict PEP 440.
    """
    parts: list[int] = []
    for part in text.split('.'):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def parse_version_iter(text: str) -> Iterable[int]:
    return parse_version(text)
