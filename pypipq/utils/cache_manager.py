"""Provides a unified cache manager with TTL and size-based eviction.

This module contains the `CacheManager` class, which offers a simple,
file-based caching mechanism. It is used to store the results of expensive
operations, such as API calls or database queries, to improve performance.
"""
import time
import pickle
import os
from pathlib import Path
from typing import Any, Optional


class CacheManager:
    """A file-based cache with Time-To-Live (TTL) and size-limiting policies.

    This class creates and manages a cache directory where arbitrary Python
    objects can be stored as serialized pickle files. Each cached item has a
    TTL, and the total size of the cache is kept below a configurable limit
    by evicting the oldest files first.

    Attributes:
        cache_dir (Path): The directory where cache files are stored.
        max_size (int): The maximum size of the cache in bytes.
    """

    def __init__(self, max_size_mb: int = 100, cache_dir: Optional[Path] = None):
        """Initializes the CacheManager.

        Args:
            max_size_mb (int): The maximum size of the cache in megabytes.
                Defaults to 100.
            cache_dir (Optional[Path]): The path to the cache directory. If
                None, a default path (`~/.cache/pipq`) is used.
        """
        self.cache_dir = cache_dir or (Path.home() / ".cache" / "pipq")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_size = max_size_mb * 1024 * 1024

    def get(self, key: str, ttl: int = 3600) -> Optional[Any]:
        """Retrieves an item from the cache if it exists and is not expired.

        Args:
            key (str): The unique key identifying the cached item.
            ttl (int): The Time-To-Live for the item in seconds. If the item
                is older than this, it is considered expired. Defaults to 3600.

        Returns:
            Optional[Any]: The deserialized Python object if found and valid,
            otherwise None.
        """
        cache_file = self.cache_dir / f"{key}.cache"
        if not cache_file.exists():
            return None

        try:
            age = time.time() - cache_file.stat().st_mtime
            if age < ttl:
                with cache_file.open('rb') as f:
                    return pickle.load(f)
        except (pickle.PickleError, EOFError, OSError):
            # If the file is corrupted or unreadable, remove it.
            cache_file.unlink(missing_ok=True)

        return None

    def set(self, key: str, value: Any) -> None:
        """Saves an item to the cache.

        Before saving, it checks if the cache needs cleanup to stay within the
        size limit.

        Args:
            key (str): The unique key for the item.
            value (Any): The Python object to be cached. It must be picklable.
        """
        self._cleanup_if_needed()
        cache_file = self.cache_dir / f"{key}.cache"
        try:
            with cache_file.open('wb') as f:
                pickle.dump(value, f)
        except (pickle.PickleError, OSError):
            # If writing fails, we simply skip caching for this item.
            pass

    def _cleanup_if_needed(self) -> None:
        """Removes the oldest cache files if the total size exceeds the limit."""
        try:
            cache_files = list(self.cache_dir.glob("*.cache"))
            if not cache_files:
                return

            # Create a list of (file, stat_result) tuples to avoid re-statting.
            files_with_stats = [(f, f.stat()) for f in cache_files]
            total_size = sum(s.st_size for _, s in files_with_stats)

            if total_size <= self.max_size:
                return

            # Sort by modification time (oldest first).
            files_with_stats.sort(key=lambda item: item[1].st_mtime)

            # Evict oldest files until the cache is within the size limit.
            while total_size > self.max_size and files_with_stats:
                oldest_file, oldest_stat = files_with_stats.pop(0)
                total_size -= oldest_stat.st_size
                oldest_file.unlink(missing_ok=True)
        except OSError:
            # If cleanup fails (e.g., due to permissions), we continue.
            pass

    def clear(self) -> None:
        """Removes all files from the cache directory."""
        try:
            for cache_file in self.cache_dir.glob("*.cache"):
                cache_file.unlink(missing_ok=True)
        except OSError:
            # Ignore errors during cleanup (e.g., file disappeared).
            pass