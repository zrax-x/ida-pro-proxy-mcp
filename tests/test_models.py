"""Tests for data models"""

import pytest
from datetime import datetime
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ida_pro_proxy_mcp.models import ProxySession, ProcessInfo, ProxyConfig


class TestProxySession:
    """Tests for ProxySession dataclass"""
    
    def test_create_session(self):
        """Test creating a session with auto-generated session_id"""
        session = ProxySession.create(
            binary_path="/path/to/binary.elf",
            process_port=8745,
            ida_session_id="1fd76"
        )
        
        assert session.session_id == "binary.elf-1fd76"
        assert session.binary_name == "binary.elf"
        assert session.process_port == 8745
        assert session.ida_session_id == "1fd76"
        assert session.is_current is False
    
    def test_create_session_with_path_normalization(self):
        """Test that binary path is normalized"""
        session = ProxySession.create(
            binary_path="./relative/path/to/crackme.exe",
            process_port=8746,
            ida_session_id="abc12"
        )
        
        assert session.session_id == "crackme.exe-abc12"
        assert session.binary_name == "crackme.exe"
        # Path should be absolute
        assert Path(session.binary_path).is_absolute()
    
    def test_touch_updates_last_accessed(self):
        """Test that touch() updates last_accessed timestamp"""
        session = ProxySession.create(
            binary_path="/path/to/test.bin",
            process_port=8745,
            ida_session_id="test1"
        )
        
        original_time = session.last_accessed
        
        # Small delay to ensure time difference
        import time
        time.sleep(0.01)
        
        session.touch()
        
        assert session.last_accessed > original_time
    
    def test_to_dict(self):
        """Test serialization to dictionary"""
        session = ProxySession.create(
            binary_path="/path/to/binary.elf",
            process_port=8745,
            ida_session_id="1fd76"
        )
        session.is_current = True
        
        data = session.to_dict()
        
        assert data["session_id"] == "binary.elf-1fd76"
        assert data["binary_name"] == "binary.elf"
        assert data["is_current"] is True
        assert "created_at" in data
        assert "last_accessed" in data
    
    def test_session_id_format(self):
        """
        Property 1: Session ID format
        For any binary path, session ID should be [binary-name]-[ida-session-id]
        """
        test_cases = [
            ("/path/to/firmware.bin", "abc12", "firmware.bin-abc12"),
            ("/home/user/crackme.elf", "xyz99", "crackme.elf-xyz99"),
            ("./relative/test.exe", "12345", "test.exe-12345"),
        ]
        
        for binary_path, ida_session, expected_id in test_cases:
            session = ProxySession.create(
                binary_path=binary_path,
                process_port=8745,
                ida_session_id=ida_session
            )
            assert session.session_id == expected_id


class TestProxyConfig:
    """Tests for ProxyConfig dataclass"""
    
    def test_default_values(self):
        """Test default configuration values"""
        config = ProxyConfig()
        
        assert config.host == "127.0.0.1"
        assert config.port == 8744
        assert config.max_processes == 2
        assert config.base_port == 8745
        assert config.request_timeout == 30
    
    def test_custom_values(self):
        """Test custom configuration values"""
        config = ProxyConfig(
            host="0.0.0.0",
            port=9000,
            max_processes=5,
            base_port=9001,
            request_timeout=60
        )
        
        assert config.host == "0.0.0.0"
        assert config.port == 9000
        assert config.max_processes == 5
        assert config.base_port == 9001
        assert config.request_timeout == 60
    
    def test_validate_valid_config(self):
        """Test validation passes for valid config"""
        config = ProxyConfig(max_processes=3)
        config.validate()  # Should not raise
    
    def test_validate_invalid_max_processes(self):
        """Test validation fails for max_processes < 1"""
        config = ProxyConfig(max_processes=0)
        
        with pytest.raises(ValueError, match="max_processes must be at least 1"):
            config.validate()
    
    def test_validate_invalid_port(self):
        """Test validation fails for invalid port"""
        config = ProxyConfig(port=0)
        
        with pytest.raises(ValueError, match="port must be between 1 and 65535"):
            config.validate()
    
    def test_validate_invalid_request_timeout(self):
        """Test validation fails for invalid request_timeout"""
        config = ProxyConfig(request_timeout=0)
        
        with pytest.raises(ValueError, match="request_timeout must be at least 1"):
            config.validate()
