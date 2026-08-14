"""Fail-closed local capacity checks before external child execution."""

from __future__ import annotations

import os
import re
import resource
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


_VM_STAT = Path("/usr/bin/vm_stat")
_PAGE_SIZE = re.compile(r"page size of ([0-9]+) bytes")
_PAGE_VALUE = re.compile(
    r"^(Pages (?:free|inactive|speculative|purgeable)):\s+([0-9]+)\.$"
)


@dataclass
class ResourceLimitError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class ResourceSnapshot:
    free_disk_bytes: int
    available_memory_bytes: int
    available_fds: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value < 0
            for value in (
                self.free_disk_bytes,
                self.available_memory_bytes,
                self.available_fds,
            )
        ):
            raise ValueError("resource snapshot values must be non-negative integers")


Probe = Callable[[Path], ResourceSnapshot]


class ResourceGate:
    def __init__(
        self,
        *,
        root: Path,
        min_free_disk_bytes: int,
        min_available_memory_bytes: int,
        min_available_fds: int,
        probe: Probe | None = None,
    ) -> None:
        thresholds = (
            min_free_disk_bytes,
            min_available_memory_bytes,
            min_available_fds,
        )
        if any(type(value) is not int or value <= 0 for value in thresholds):
            raise ValueError("resource thresholds must be positive integers")
        self.root = root.expanduser().resolve()
        self.min_free_disk_bytes = min_free_disk_bytes
        self.min_available_memory_bytes = min_available_memory_bytes
        self.min_available_fds = min_available_fds
        self._probe = probe or probe_resources

    def require_capacity(self) -> ResourceSnapshot:
        try:
            snapshot = self._probe(self.root)
        except Exception as exc:
            raise ResourceLimitError(
                "RESOURCE_PROBE_FAILED",
                "local resource capacity could not be measured",
            ) from exc
        checks = (
            (
                snapshot.free_disk_bytes,
                self.min_free_disk_bytes,
                "DISK_CAPACITY_EXHAUSTED",
            ),
            (
                snapshot.available_memory_bytes,
                self.min_available_memory_bytes,
                "MEMORY_CAPACITY_EXHAUSTED",
            ),
            (
                snapshot.available_fds,
                self.min_available_fds,
                "FD_CAPACITY_EXHAUSTED",
            ),
        )
        for observed, required, code in checks:
            if observed < required:
                raise ResourceLimitError(
                    code,
                    f"observed {observed}, required at least {required}",
                )
        return snapshot


def probe_resources(root: Path) -> ResourceSnapshot:
    root = root.resolve(strict=True)
    disk = shutil.disk_usage(root)
    memory = _available_memory_bytes()
    soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft_limit == resource.RLIM_INFINITY:
        available_fds = 2**31 - 1
    else:
        open_fds = len(os.listdir("/dev/fd"))
        available_fds = max(0, int(soft_limit) - open_fds)
    return ResourceSnapshot(
        free_disk_bytes=int(disk.free),
        available_memory_bytes=memory,
        available_fds=available_fds,
    )


def _available_memory_bytes() -> int:
    result = subprocess.run(
        [os.fspath(_VM_STAT)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=3,
        check=False,
        shell=False,
    )
    if result.returncode != 0:
        raise OSError(result.stderr.strip() or "vm_stat failed")
    return parse_vm_stat(result.stdout)


def parse_vm_stat(output: str) -> int:
    lines = output.splitlines()
    if not lines:
        raise ValueError("vm_stat output is empty")
    page_match = _PAGE_SIZE.search(lines[0])
    if page_match is None:
        raise ValueError("vm_stat page size is missing")
    page_size = int(page_match.group(1))
    pages: dict[str, int] = {}
    for line in lines[1:]:
        match = _PAGE_VALUE.fullmatch(line.strip())
        if match is not None:
            pages[match.group(1)] = int(match.group(2))
    required = {
        "Pages free",
        "Pages inactive",
        "Pages speculative",
        "Pages purgeable",
    }
    if set(pages) != required:
        raise ValueError("vm_stat available-page fields are incomplete")
    return sum(pages.values()) * page_size
