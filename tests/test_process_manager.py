"""Tests for ProcessManager"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ida_pro_proxy_mcp.process_manager import ProcessManager


class TestPortAllocation:
    """Tests for port allocation logic - Property 9"""
    
    def test_allocate_port_starts_from_base(self):
        """Test that first port allocation starts from BASE_PORT"""
        manager = ProcessManager()
        
        port = manager.allocate_port()
        
        assert port == ProcessManager.BASE_PORT
    
    def test_allocate_port_increments(self):
        """Test that subsequent allocations increment port"""
        manager = ProcessManager()
        
        port1 = manager.allocate_port()
        port2 = manager.allocate_port()
        port3 = manager.allocate_port()
        
        assert port1 == ProcessManager.BASE_PORT
        assert port2 == ProcessManager.BASE_PORT + 1
        assert port3 == ProcessManager.BASE_PORT + 2
    
    def test_release_port_allows_reuse(self):
        """Test that released ports can be reused"""
        manager = ProcessManager()
        
        port1 = manager.allocate_port()
        port2 = manager.allocate_port()
        
        manager.release_port(port1)
        
        # Next allocation should reuse released port
        port3 = manager.allocate_port()
        
        assert port3 == port1
    
    def test_port_uniqueness(self):
        """
        Property 9: Port allocation uniqueness
        For any two active processes, their ports should be unique
        """
        manager = ProcessManager()
        
        allocated_ports = set()
        for _ in range(10):
            port = manager.allocate_port()
            assert port not in allocated_ports, f"Port {port} was allocated twice"
            allocated_ports.add(port)
    
    def test_port_recycling(self):
        """
        Property 9: Port recycling
        Released ports should be available for reuse
        """
        manager = ProcessManager()
        
        # Allocate some ports
        ports = [manager.allocate_port() for _ in range(5)]
        
        # Release middle ports
        manager.release_port(ports[1])
        manager.release_port(ports[3])
        
        # New allocations should reuse released ports
        new_port1 = manager.allocate_port()
        new_port2 = manager.allocate_port()
        
        assert new_port1 in [ports[1], ports[3]]
        assert new_port2 in [ports[1], ports[3]]
        assert new_port1 != new_port2


class TestProcessLifecycle:
    """Tests for process lifecycle management"""
    
    @patch('ida_pro_proxy_mcp.process_manager.subprocess.Popen')
    def test_start_process_success(self, mock_popen):
        """Test successful process start"""
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Process is running
        mock_process.pid = 12345
        mock_popen.return_value = mock_process
        
        manager = ProcessManager()
        
        with patch('time.sleep'):  # Skip sleep
            info = manager.start_process()
        
        assert info.port == ProcessManager.BASE_PORT
        assert info.pid == 12345
        assert manager.process_count == 1
    
    @patch('ida_pro_proxy_mcp.process_manager.subprocess.Popen')
    def test_start_process_failure(self, mock_popen):
        """Test process start failure"""
        mock_process = MagicMock()
        mock_process.poll.return_value = 1  # Process exited
        mock_process.communicate.return_value = (b"", b"Error message")
        mock_popen.return_value = mock_process
        
        manager = ProcessManager()
        
        with patch('time.sleep'):
            with pytest.raises(RuntimeError, match="exited immediately"):
                manager.start_process()
        
        # Port should be released on failure
        assert manager.process_count == 0
    
    @patch('ida_pro_proxy_mcp.process_manager.subprocess.Popen')
    def test_stop_process(self, mock_popen):
        """Test stopping a process"""
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345
        mock_popen.return_value = mock_process
        
        manager = ProcessManager()
        
        with patch('time.sleep'):
            info = manager.start_process()
        
        port = info.port
        result = manager.stop_process(port)
        
        assert result is True
        assert manager.process_count == 0
        mock_process.terminate.assert_called_once()
    
    def test_stop_nonexistent_process(self):
        """Test stopping a process that doesn't exist"""
        manager = ProcessManager()
        
        result = manager.stop_process(9999)
        
        assert result is False
    
    @patch('ida_pro_proxy_mcp.process_manager.subprocess.Popen')
    def test_stop_all(self, mock_popen):
        """Test stopping all processes"""
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345
        mock_popen.return_value = mock_process
        
        manager = ProcessManager()
        
        with patch('time.sleep'):
            manager.start_process()
            manager.start_process()
            manager.start_process()
        
        assert manager.process_count == 3
        
        manager.stop_all()
        
        assert manager.process_count == 0


class TestProcessHealth:
    """Tests for process health checking"""
    
    @patch('ida_pro_proxy_mcp.process_manager.subprocess.Popen')
    def test_check_healthy_process(self, mock_popen):
        """Test health check for running process"""
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Running
        mock_process.pid = 12345
        mock_popen.return_value = mock_process
        
        manager = ProcessManager()
        
        with patch('time.sleep'):
            info = manager.start_process()
        
        assert manager.check_process_health(info.port) is True
    
    @patch('ida_pro_proxy_mcp.process_manager.subprocess.Popen')
    def test_check_crashed_process(self, mock_popen):
        """Test health check for crashed process"""
        mock_process = MagicMock()
        mock_process.poll.side_effect = [None, 1]  # First running, then crashed
        mock_process.pid = 12345
        mock_popen.return_value = mock_process
        
        manager = ProcessManager()
        
        with patch('time.sleep'):
            info = manager.start_process()
        
        # Process crashed
        assert manager.check_process_health(info.port) is False
    
    def test_check_nonexistent_process(self):
        """Test health check for nonexistent process"""
        manager = ProcessManager()
        
        assert manager.check_process_health(9999) is False


class TestRequestForwarding:
    """Tests for request forwarding"""
    
    @patch('ida_pro_proxy_mcp.process_manager.http.client.HTTPConnection')
    @patch('ida_pro_proxy_mcp.process_manager.subprocess.Popen')
    def test_forward_request_success(self, mock_popen, mock_http):
        """Test successful request forwarding"""
        # Setup process
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345
        mock_popen.return_value = mock_process
        
        # Setup HTTP response
        mock_conn = MagicMock()
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"jsonrpc": "2.0", "id": 1, "result": {}}'
        mock_conn.getresponse.return_value = mock_response
        mock_http.return_value = mock_conn
        
        manager = ProcessManager()
        
        with patch('time.sleep'):
            info = manager.start_process()
        
        request = {"jsonrpc": "2.0", "id": 1, "method": "test"}
        response = manager.forward_request(info.port, request)
        
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 1
    
    @patch('ida_pro_proxy_mcp.process_manager.subprocess.Popen')
    def test_forward_request_to_unhealthy_process(self, mock_popen):
        """Test forwarding to unhealthy process raises error"""
        mock_process = MagicMock()
        mock_process.poll.side_effect = [None, 1]  # First running, then crashed
        mock_process.pid = 12345
        mock_popen.return_value = mock_process
        
        manager = ProcessManager()
        
        with patch('time.sleep'):
            info = manager.start_process()
        
        with pytest.raises(RuntimeError, match="not healthy"):
            manager.forward_request(info.port, {"test": "request"})
