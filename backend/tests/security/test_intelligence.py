"""Unit tests for Process Intelligence Engine."""

import hashlib
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import psutil

from backend.security.cache import ProcessIntelligenceCache
from backend.security.hashing import calculate_sha256
from backend.security.intelligence import get_process_info
from backend.security.models import ProcessInfo
from backend.security.providers.windows import WindowsProcessProvider


class TestProcessInfoModel:
    """Test ProcessInfo dataclass methods."""

    def test_process_info_to_dict(self):
        info = ProcessInfo(
            pid=1234,
            name="test.exe",
            exe_path="C:\\test.exe",
            sha256="a" * 64,
            is_elevated=True,
        )
        data = info.to_dict()
        assert data["pid"] == 1234
        assert data["name"] == "test.exe"
        assert data["exe_path"] == "C:\\test.exe"
        assert data["sha256"] == "a" * 64
        assert data["is_elevated"] is True
        assert data["access_denied"] is False

    def test_process_info_is_complete(self):
        complete = ProcessInfo(
            pid=100, name="app.exe", exe_path="C:\\app.exe", sha256="b" * 64
        )
        assert complete.is_complete is True

        incomplete = ProcessInfo(pid=100, name="app.exe", exe_path=None)
        assert incomplete.is_complete is False

        with_error = ProcessInfo(
            pid=100,
            name="app.exe",
            exe_path="C:\\app.exe",
            sha256="b" * 64,
            error_message="Access restricted",
        )
        assert with_error.is_complete is False


class TestHashing:
    """Test SHA-256 file hashing module."""

    def test_calculate_sha256_success(self, tmp_path: Path):
        test_file = tmp_path / "sample.bin"
        content = b"AI Firewall Security Test Payload"
        test_file.write_bytes(content)

        expected_hash = hashlib.sha256(content).hexdigest()
        calculated_hash = calculate_sha256(test_file)

        assert calculated_hash == expected_hash

    def test_calculate_sha256_non_existent_file(self, tmp_path: Path):
        missing_file = tmp_path / "does_not_exist.exe"
        assert calculate_sha256(missing_file) is None

    def test_calculate_sha256_directory(self, tmp_path: Path):
        assert calculate_sha256(tmp_path) is None

    def test_calculate_sha256_permission_error(self, tmp_path: Path):
        test_file = tmp_path / "protected.bin"
        test_file.write_bytes(b"data")

        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            assert calculate_sha256(test_file) is None


class TestProcessIntelligenceCache:
    """Test ProcessIntelligenceCache behavior."""

    def test_process_info_cache_hit_and_miss(self):
        cache = ProcessIntelligenceCache(metadata_ttl=60.0)
        assert cache.get_process_info(1234) is None

        info = ProcessInfo(pid=1234, name="cached.exe")
        cache.set_process_info(info)

        cached = cache.get_process_info(1234)
        assert cached is not None
        assert cached.name == "cached.exe"

    def test_process_info_cache_expiration(self):
        cache = ProcessIntelligenceCache(metadata_ttl=0.01)
        info = ProcessInfo(pid=1234, name="expired.exe")
        cache.set_process_info(info)

        import time

        time.sleep(0.02)
        assert cache.get_process_info(1234) is None

    def test_hash_cache_hit_and_invalidation(self, tmp_path: Path):
        cache = ProcessIntelligenceCache()
        sample_file = tmp_path / "test.dll"
        sample_file.write_bytes(b"v1")

        assert cache.get_hash(sample_file) is None
        cache.set_hash(sample_file, "hash123")
        assert cache.get_hash(sample_file) == "hash123"

        # Modify file content
        import time

        time.sleep(0.01)
        sample_file.write_bytes(b"v2_modified")
        assert cache.get_hash(sample_file) is None


class TestWindowsProcessProvider:
    """Test WindowsProcessProvider inspection and exception handling."""

    def test_current_process_inspection(self):
        current_pid = os.getpid()
        provider = WindowsProcessProvider()
        info = provider.get_process_info(current_pid)

        assert info.pid == current_pid
        assert info.name is not None
        assert info.exe_path is not None
        assert info.sha256 is not None
        assert info.access_denied is False
        assert info.error_message is None

    def test_non_existent_process(self):
        provider = WindowsProcessProvider()
        info = provider.get_process_info(9999999)

        assert info.pid == 9999999
        assert info.name is None
        assert info.error_message is not None
        assert "not found" in info.error_message.lower()

    def test_access_denied_on_init(self):
        provider = WindowsProcessProvider()
        with patch("psutil.Process", side_effect=psutil.AccessDenied(pid=500)):
            info = provider.get_process_info(500)

        assert info.pid == 500
        assert info.access_denied is True
        assert "Access denied" in info.error_message

    def test_zombie_process_on_init(self):
        provider = WindowsProcessProvider()
        with patch("psutil.Process", side_effect=psutil.ZombieProcess(pid=600)):
            info = provider.get_process_info(600)

        assert info.pid == 600
        assert info.status == "zombie"
        assert "zombie" in info.error_message.lower()

    def test_partial_access_denied(self):
        mock_proc = MagicMock()
        mock_proc.pid = 700
        mock_proc.name.return_value = "system_service.exe"
        mock_proc.exe.side_effect = psutil.AccessDenied(pid=700)
        mock_proc.cmdline.side_effect = psutil.AccessDenied(pid=700)
        mock_proc.username.side_effect = psutil.AccessDenied(pid=700)
        mock_proc.create_time.return_value = 1600000000.0
        mock_proc.ppid.return_value = 4
        mock_proc.status.return_value = "running"
        mock_proc.cpu_percent.return_value = 0.5
        mock_proc.memory_info.return_value = MagicMock(rss=1024, vms=2048)

        provider = WindowsProcessProvider()
        with patch("psutil.Process", return_value=mock_proc):
            info = provider.get_process_info(700)

        assert info.pid == 700
        assert info.name == "system_service.exe"
        assert info.exe_path is None
        assert info.username is None
        assert info.access_denied is True
        assert info.parent_pid == 4
        assert info.memory_rss == 1024


class TestProcessIntelligenceEngine:
    """Test ProcessIntelligenceEngine top-level interface."""

    def test_engine_get_process_info_current_pid(self):
        current_pid = os.getpid()
        info = get_process_info(current_pid, use_cache=True)
        assert info.pid == current_pid
        assert info.name is not None

        # Verify caching returns identical object on second call
        info_cached = get_process_info(current_pid, use_cache=True)
        assert info_cached is info

    def test_engine_use_cache_false(self):
        current_pid = os.getpid()
        info1 = get_process_info(current_pid, use_cache=True)
        info2 = get_process_info(current_pid, use_cache=False)

        assert info1.pid == info2.pid
        assert info1 is not info2  # Re-fetched, different instance
