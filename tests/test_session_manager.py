"""Tests for SessionManager with LRU"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ida_pro_proxy_mcp.session_manager import SessionManager
from ida_pro_proxy_mcp.process_manager import ProcessManager


@pytest.fixture
def mock_process_manager():
    """Create a mock ProcessManager"""
    manager = Mock(spec=ProcessManager)
    manager.process_count = 0
    
    def start_process_side_effect(*args, **kwargs):
        manager.process_count += 1
        mock_info = MagicMock()
        mock_info.port = 8744 + manager.process_count
        mock_info.pid = 10000 + manager.process_count
        mock_info.is_alive.return_value = True
        mock_info.current_ida_session = None
        return mock_info
    
    def stop_process_side_effect(port):
        manager.process_count -= 1
        return True
    
    manager.start_process.side_effect = start_process_side_effect
    manager.stop_process.side_effect = stop_process_side_effect
    manager.check_process_health.return_value = True
    
    # Mock forward_request to return successful idalib_open response
    manager.forward_request.return_value = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "success": True,
            "session": {
                "session_id": "abc12",
                "input_path": "/path/to/binary",
                "filename": "binary",
            }
        }
    }
    
    return manager


@pytest.fixture
def temp_binary():
    """Create a temporary binary file for testing"""
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        f.write(b"\x7fELF")  # ELF magic
        return Path(f.name)


class TestSessionOpen:
    """Tests for session opening"""
    
    def test_open_session_creates_new(self, mock_process_manager, temp_binary):
        """Test opening a new session"""
        manager = SessionManager(max_processes=2, process_manager=mock_process_manager)
        
        session = manager.open_session(str(temp_binary))
        
        assert session is not None
        assert session.binary_name == temp_binary.name
        assert session.is_current is True
        assert manager.session_count == 1
    
    def test_open_same_binary_returns_existing(self, mock_process_manager, temp_binary):
        """
        Property 2: Same binary returns same session
        Opening the same binary twice should return the existing session
        """
        manager = SessionManager(max_processes=2, process_manager=mock_process_manager)
        
        session1 = manager.open_session(str(temp_binary))
        session2 = manager.open_session(str(temp_binary))
        
        assert session1.session_id == session2.session_id
        assert manager.session_count == 1
        # Process should only be started once
        assert mock_process_manager.start_process.call_count == 1
    
    def test_open_nonexistent_file_raises(self, mock_process_manager):
        """Test opening nonexistent file raises FileNotFoundError"""
        manager = SessionManager(max_processes=2, process_manager=mock_process_manager)
        
        with pytest.raises(FileNotFoundError):
            manager.open_session("/nonexistent/path/to/binary.elf")


class TestLRUEviction:
    """Tests for LRU eviction - Property 3"""
    
    def test_lru_eviction_when_max_reached(self, mock_process_manager):
        """
        Property 3: LRU eviction correctness
        When max_processes is reached, oldest session should be evicted
        """
        manager = SessionManager(max_processes=2, process_manager=mock_process_manager)
        
        # Create temp files
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f1:
            f1.write(b"binary1")
            binary1 = f1.name
        
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f2:
            f2.write(b"binary2")
            binary2 = f2.name
        
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f3:
            f3.write(b"binary3")
            binary3 = f3.name
        
        # Open first two sessions
        session1 = manager.open_session(binary1)
        session2 = manager.open_session(binary2)
        
        assert manager.session_count == 2
        
        # Opening third should evict first (LRU)
        session3 = manager.open_session(binary3)
        
        assert manager.session_count == 2
        assert manager.get_session(session1.session_id) is None  # Evicted
        assert manager.get_session(session2.session_id) is not None
        assert manager.get_session(session3.session_id) is not None
    
    def test_lru_order_updated_on_access(self, mock_process_manager):
        """Test that accessing a session updates its LRU position"""
        manager = SessionManager(max_processes=2, process_manager=mock_process_manager)
        
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f1:
            f1.write(b"binary1")
            binary1 = f1.name
        
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f2:
            f2.write(b"binary2")
            binary2 = f2.name
        
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f3:
            f3.write(b"binary3")
            binary3 = f3.name
        
        session1 = manager.open_session(binary1)
        session2 = manager.open_session(binary2)
        
        # Access session1 to make it more recent
        manager.switch_session(session1.session_id)
        
        # Opening third should evict session2 (now LRU)
        session3 = manager.open_session(binary3)
        
        assert manager.get_session(session1.session_id) is not None  # Still exists
        assert manager.get_session(session2.session_id) is None  # Evicted
        assert manager.get_session(session3.session_id) is not None


class TestSessionClose:
    """Tests for session closing - Property 6"""
    
    def test_close_session_terminates_process(self, mock_process_manager, temp_binary):
        """
        Property 6: Session close terminates process
        Closing a session should terminate its process
        """
        manager = SessionManager(max_processes=2, process_manager=mock_process_manager)
        
        session = manager.open_session(str(temp_binary))
        port = session.process_port
        
        result = manager.close_session(session.session_id)
        
        assert result is True
        assert manager.session_count == 0
        mock_process_manager.stop_process.assert_called_with(port)
    
    def test_close_nonexistent_session(self, mock_process_manager):
        """Test closing nonexistent session returns False"""
        manager = SessionManager(max_processes=2, process_manager=mock_process_manager)
        
        result = manager.close_session("nonexistent-session")
        
        assert result is False


class TestSessionSwitch:
    """Tests for session switching - Property 5"""
    
    def test_switch_session_updates_current(self, mock_process_manager):
        """
        Property 5: Session switch updates current
        Switching should update the current active session
        """
        manager = SessionManager(max_processes=2, process_manager=mock_process_manager)
        
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f1:
            f1.write(b"binary1")
            binary1 = f1.name
        
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f2:
            f2.write(b"binary2")
            binary2 = f2.name
        
        session1 = manager.open_session(binary1)
        session2 = manager.open_session(binary2)
        
        # session2 should be current
        assert manager.get_current_session().session_id == session2.session_id
        
        # Switch to session1
        manager.switch_session(session1.session_id)
        
        assert manager.get_current_session().session_id == session1.session_id
    
    def test_switch_to_nonexistent_raises(self, mock_process_manager):
        """Test switching to nonexistent session raises ValueError"""
        manager = SessionManager(max_processes=2, process_manager=mock_process_manager)
        
        with pytest.raises(ValueError, match="Session not found"):
            manager.switch_session("nonexistent-session")


class TestSessionList:
    """Tests for session listing - Property 4"""
    
    def test_list_sessions_returns_all(self, mock_process_manager):
        """
        Property 4: Session list consistency
        list_sessions should return all active sessions
        """
        manager = SessionManager(max_processes=3, process_manager=mock_process_manager)
        
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f1:
            f1.write(b"binary1")
            binary1 = f1.name
        
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f2:
            f2.write(b"binary2")
            binary2 = f2.name
        
        session1 = manager.open_session(binary1)
        session2 = manager.open_session(binary2)
        
        sessions = manager.list_sessions()
        
        assert len(sessions) == 2
        session_ids = [s["session_id"] for s in sessions]
        assert session1.session_id in session_ids
        assert session2.session_id in session_ids
    
    def test_list_sessions_shows_current(self, mock_process_manager, temp_binary):
        """Test that list_sessions correctly marks current session"""
        manager = SessionManager(max_processes=2, process_manager=mock_process_manager)
        
        session = manager.open_session(str(temp_binary))
        
        sessions = manager.list_sessions()
        
        assert len(sessions) == 1
        assert sessions[0]["is_current"] is True


class TestProcessCountInvariant:
    """Tests for process count invariant - Property 10"""
    
    def test_process_count_never_exceeds_max(self, mock_process_manager):
        """
        Property 10: Process count invariant
        Number of processes should never exceed max_processes
        """
        max_procs = 3
        manager = SessionManager(max_processes=max_procs, process_manager=mock_process_manager)
        
        # Create many temp files
        binaries = []
        for i in range(10):
            with tempfile.NamedTemporaryFile(suffix=f"_{i}.bin", delete=False) as f:
                f.write(f"binary{i}".encode())
                binaries.append(f.name)
        
        # Open all binaries
        for binary in binaries:
            manager.open_session(binary)
            assert manager.session_count <= max_procs
        
        # Final count should be max_processes
        assert manager.session_count == max_procs
