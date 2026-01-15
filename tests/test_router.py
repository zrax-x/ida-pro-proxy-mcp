"""Tests for RequestRouter"""

import pytest
import json
from pathlib import Path
from unittest.mock import Mock, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ida_pro_proxy_mcp.router import RequestRouter
from ida_pro_proxy_mcp.session_manager import SessionManager
from ida_pro_proxy_mcp.models import ProxySession


@pytest.fixture
def mock_session_manager():
    """Create a mock SessionManager"""
    manager = Mock(spec=SessionManager)
    manager.process_manager = Mock()
    manager.process_manager.check_process_health.return_value = True
    manager.process_manager.forward_request.return_value = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": "{}"}]}
    }
    return manager


@pytest.fixture
def mock_session():
    """Create a mock ProxySession"""
    session = Mock(spec=ProxySession)
    session.session_id = "test.elf-abc12"
    session.binary_path = "/path/to/test.elf"
    session.binary_name = "test.elf"
    session.process_port = 8745
    session.ida_session_id = "abc12"
    session.is_current = True
    session.to_dict.return_value = {
        "session_id": "test.elf-abc12",
        "binary_path": "/path/to/test.elf",
        "binary_name": "test.elf",
        "is_current": True,
    }
    return session


class TestInitialize:
    """Tests for MCP initialize handling"""
    
    def test_handle_initialize(self, mock_session_manager):
        """Test initialize request returns server info"""
        router = RequestRouter(mock_session_manager)
        
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }
        
        response = router.route(request)
        
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 1
        assert "result" in response
        assert response["result"]["serverInfo"]["name"] == "ida-pro-proxy-mcp"


class TestSessionTools:
    """Tests for session management tools"""
    
    def test_handle_idalib_open(self, mock_session_manager, mock_session):
        """Test idalib_open tool"""
        mock_session_manager.open_session.return_value = mock_session
        router = RequestRouter(mock_session_manager)
        
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "idalib_open",
                "arguments": {
                    "input_path": "/path/to/binary.elf"
                }
            }
        }
        
        response = router.route(request)
        
        assert response["id"] == 1
        assert "result" in response
        mock_session_manager.open_session.assert_called_once()
    
    def test_handle_idalib_close(self, mock_session_manager):
        """Test idalib_close tool"""
        mock_session_manager.close_session.return_value = True
        router = RequestRouter(mock_session_manager)
        
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "idalib_close",
                "arguments": {
                    "session_id": "test.elf-abc12"
                }
            }
        }
        
        response = router.route(request)
        
        assert response["id"] == 1
        mock_session_manager.close_session.assert_called_with("test.elf-abc12")
    
    def test_handle_idalib_switch(self, mock_session_manager, mock_session):
        """Test idalib_switch tool"""
        mock_session_manager.switch_session.return_value = mock_session
        router = RequestRouter(mock_session_manager)
        
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "idalib_switch",
                "arguments": {
                    "session_id": "test.elf-abc12"
                }
            }
        }
        
        response = router.route(request)
        
        assert response["id"] == 1
        mock_session_manager.switch_session.assert_called_with("test.elf-abc12")
    
    def test_handle_idalib_list(self, mock_session_manager, mock_session):
        """Test idalib_list tool"""
        mock_session_manager.list_sessions.return_value = [mock_session.to_dict()]
        mock_session_manager.get_current_session.return_value = mock_session
        router = RequestRouter(mock_session_manager)
        
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "idalib_list",
                "arguments": {}
            }
        }
        
        response = router.route(request)
        
        assert response["id"] == 1
        # Verify both content and structuredContent are present
        assert "content" in response["result"]
        assert "structuredContent" in response["result"]
        result_text = response["result"]["content"][0]["text"]
        result = json.loads(result_text)
        assert "sessions" in result
        assert result["count"] == 1
        # Verify structuredContent matches
        assert response["result"]["structuredContent"]["count"] == 1
    
    def test_handle_idalib_current(self, mock_session_manager, mock_session):
        """Test idalib_current tool"""
        mock_session_manager.get_current_session.return_value = mock_session
        router = RequestRouter(mock_session_manager)
        
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "idalib_current",
                "arguments": {}
            }
        }
        
        response = router.route(request)
        
        assert response["id"] == 1
        result_text = response["result"]["content"][0]["text"]
        result = json.loads(result_text)
        assert result["session_id"] == "test.elf-abc12"
    
    def test_handle_idalib_current_no_session(self, mock_session_manager):
        """Test idalib_current when no session is active"""
        mock_session_manager.get_current_session.return_value = None
        router = RequestRouter(mock_session_manager)
        
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "idalib_current",
                "arguments": {}
            }
        }
        
        response = router.route(request)
        
        assert response["id"] == 1
        assert response["result"]["isError"] is True


class TestAnalysisToolRouting:
    """Tests for analysis tool routing - Properties 7 and 8"""
    
    def test_route_with_session_param(self, mock_session_manager, mock_session):
        """
        Property 7: Request routing with session parameter
        Tools with session param should route to correct process
        """
        mock_session_manager.get_session.return_value = mock_session
        router = RequestRouter(mock_session_manager)
        
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "decompile",
                "arguments": {
                    "addr": "0x401000",
                    "session": "test.elf-abc12"
                }
            }
        }
        
        response = router.route(request)
        
        mock_session_manager.get_session.assert_called_with("test.elf-abc12")
        mock_session_manager.process_manager.forward_request.assert_called()
    
    def test_route_without_session_uses_current(self, mock_session_manager, mock_session):
        """
        Property 8: Default session routing
        Tools without session param should use current session
        """
        mock_session_manager.get_session.return_value = None
        mock_session_manager.get_current_session.return_value = mock_session
        router = RequestRouter(mock_session_manager)
        
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "decompile",
                "arguments": {
                    "addr": "0x401000"
                }
            }
        }
        
        response = router.route(request)
        
        mock_session_manager.get_current_session.assert_called()
        mock_session_manager.process_manager.forward_request.assert_called()
    
    def test_route_invalid_session_returns_error(self, mock_session_manager):
        """Test routing with invalid session returns error"""
        mock_session_manager.get_session.return_value = None
        router = RequestRouter(mock_session_manager)
        
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "decompile",
                "arguments": {
                    "addr": "0x401000",
                    "session": "nonexistent-session"
                }
            }
        }
        
        response = router.route(request)
        
        assert response["result"]["isError"] is True
        result_text = response["result"]["content"][0]["text"]
        assert "Session not found" in result_text
    
    def test_route_no_active_session_returns_error(self, mock_session_manager):
        """Test routing without active session returns error"""
        mock_session_manager.get_session.return_value = None
        mock_session_manager.get_current_session.return_value = None
        router = RequestRouter(mock_session_manager)
        
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "decompile",
                "arguments": {
                    "addr": "0x401000"
                }
            }
        }
        
        response = router.route(request)
        
        assert response["result"]["isError"] is True
        result_text = response["result"]["content"][0]["text"]
        assert "No active session" in result_text


class TestCrashDetection:
    """Tests for crash detection - Property 11"""
    
    def test_detect_crashed_process(self, mock_session_manager, mock_session):
        """
        Property 11: Crash detection
        Should detect crashed process and return error
        """
        mock_session_manager.get_session.return_value = mock_session
        mock_session_manager.process_manager.check_process_health.return_value = False
        router = RequestRouter(mock_session_manager)
        
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "decompile",
                "arguments": {
                    "addr": "0x401000",
                    "session": "test.elf-abc12"
                }
            }
        }
        
        response = router.route(request)
        
        assert response["result"]["isError"] is True
        result_text = response["result"]["content"][0]["text"]
        assert "no longer available" in result_text
        # Session should be closed
        mock_session_manager.close_session.assert_called_with("test.elf-abc12")
