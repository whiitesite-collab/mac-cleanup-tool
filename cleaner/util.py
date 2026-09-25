"""Small helpers shared by the scanners."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Iterable, Iterator, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def parallel_map(func: Callable[[T], R], items: Iterable[T], max_workers: int = 8) -> list[R]:
    """Run func over items concurrently. Scanning is I/O-bound (stat/read calls
    release the GIL), so a thread pool speeds up walking several unrelated
    directories or hashing several files without any extra process overhead."""
    items = list(items)
    if len(items) <= 1:
        return [func(item) for item in items]
    with ThreadPoolExecutor(max_workers=min(max_workers, len(items))) as pool:
        return list(pool.map(func, items))


def iter_files(root: Path) -> Iterator[tuple[Path, os.stat_result]]:
    """Walk root and yield (path, stat_result) for every regular file, doing
    exactly one stat() per file instead of the is_file() + stat() + suffix
    pattern repeating the syscall. Symlinks are skipped entirely: symlinked
    directories would risk cycles, and a symlinked file is not a file of its
    own - it would show up as a "duplicate" of its target (trashing the real
    file would leave the link dangling) and removing it frees no space."""
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    stack.append(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    yield Path(entry.path), entry.stat(follow_symlinks=False)
            except OSError:
                continue
