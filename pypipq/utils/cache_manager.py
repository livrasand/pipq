# Copyright (C) 2025 Livrädo Sandoval
# Licensed under GPL-3.0

"""
Unified cache manager with TTL and size limits.
"""
import time
import pickle
import os
from pathlib import Path
from typing import Any, Optional


class CacheManager:
    """Unified cache with TTL and size limits"""

    def __init__(self, max_size_mb: int = 100, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or (Path.home() / ".cache" / "pipq")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_size = max_size_mb * 1024 * 1024

    def get(self, key: str, ttl: int = 3600) -> Optional[Any]:
        cache_file = self.cache_dir / f"{key}.cache"
        if cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < ttl:
                try:
                    with cache_file.open('rb') as f:
                        return pickle.load(f)
                except (pickle.PickleError, EOFError):
                    # Corrupted cache file, remove it
                    cache_file.unlink(missing_ok=True)
        return None

    def set(self, key: str, value: Any) -> None:
        self._cleanup_if_needed()
        cache_file = self.cache_dir / f"{key}.cache"
        try:
            with cache_file.open('wb') as f:
                pickle.dump(value, f)
        except (pickle.PickleError, OSError):
            # If we can't write, just skip caching
            pass

    def _cleanup_if_needed(self) -> None:
        """Remove old cache files if total size exceeds limit"""
        try:
            cache_files = list(self.cache_dir.glob("*.cache"))
            if not cache_files:
                return

            # Sort by modification time (oldest first)
            cache_files.sort(key=lambda f: f.stat().st_mtime)

            total_size = sum(f.stat().st_size for f in cache_files)

            # Remove oldest files until we're under the limit
            while total_size > self.max_size and cache_files:
                oldest = cache_files.pop(0)
                total_size -= oldest.stat().st_size
                oldest.unlink(missing_ok=True)
        except OSError:
            # If cleanup fails, just continue
            pass

    def clear(self) -> None:
        """Clear all cache files"""
        try:
            for cache_file in self.cache_dir.glob("*.cache"):
                cache_file.unlink(missing_ok=True)
        except OSError:
            pass