"""Session Manager with LRU eviction for IDA Pro Proxy MCP"""

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from .models import ProxySession
from .process_manager import ProcessManager

logger = logging.getLogger(__name__)


class SessionManager:
    """Manages proxy sessions with LRU eviction.
    
    Sessions are mapped to idalib-mcp processes. Processes can be reused
    when sessions are closed or evicted. When the maximum number of processes
    is reached, the least recently used session is evicted and its process
    is reused for the new session.
    """
    
    def __init__(self, max_processes: int, process_manager: ProcessManager):
        """Initialize the session manager.
        
        Args:
            max_processes: Maximum number of concurrent sessions/processes
            process_manager: ProcessManager instance for managing child processes
        """
        self.max_processes = max_processes
        self.process_manager = process_manager
        self._sessions: Dict[str, ProxySession] = {}  # session_id -> ProxySession
        self._binary_to_session: Dict[str, str] = {}  # binary_path -> session_id
        self._port_to_session: Dict[int, str] = {}  # port -> session_id (for tracking which ports have sessions)
        self._current_session_id: Optional[str] = None
        self._lru_order: List[str] = []  # session_ids in LRU order (oldest first)
        self._lock = threading.RLock()
    
    def _update_lru(self, session_id: str) -> None:
        """Move session to end of LRU list (most recently used).
        
        Args:
            session_id: Session ID to update
        """
        if session_id in self._lru_order:
            self._lru_order.remove(session_id)
        self._lru_order.append(session_id)
    
    def _get_idle_port(self) -> Optional[int]:
        """Get a port of an idle process (process without active session).
        
        Returns:
            Port number of idle process, or None if no idle processes
        """
        active_ports = self.process_manager.active_ports
        for port in active_ports:
            if port not in self._port_to_session:
                return port
        return None
    
    def _evict_lru_for_reuse(self) -> Optional[int]:
        """Evict the least recently used session and return its process port.
        
        This closes the IDA session but keeps the process running for reuse.
        
        Returns:
            Port of the evicted session's process, or None if no sessions
        """
        if not self._lru_order:
            return None
        
        # Get oldest session (front of list)
        oldest_session_id = self._lru_order[0]
        session = self._sessions.get(oldest_session_id)
        
        if session is None:
            self._lru_order.pop(0)
            return None
        
        logger.info(f"Evicting LRU session: {oldest_session_id}")
        
        # Get the port before closing
        port = session.process_port
        
        # Close the IDA session on the process (but don't terminate the process)
        try:
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "idalib_close",
                    "arguments": {
                        "session_id": session.ida_session_id,
                    }
                }
            }
            self.process_manager.forward_request(port, request)
        except Exception as e:
            logger.warning(f"Failed to close IDA session during eviction: {e}")
        
        # Remove session from our tracking
        self._sessions.pop(oldest_session_id, None)
        self._binary_to_session.pop(session.binary_path, None)
        self._port_to_session.pop(port, None)
        self._lru_order.pop(0)
        
        # Update current session if needed
        if self._current_session_id == oldest_session_id:
            self._current_session_id = self._lru_order[-1] if self._lru_order else None
            if self._current_session_id and self._current_session_id in self._sessions:
                self._sessions[self._current_session_id].is_current = True
        
        logger.info(f"Evicted session: {oldest_session_id}, process on port {port} available for reuse")
        return port
    
    def open_session(self, binary_path: str, run_auto_analysis: bool = True) -> ProxySession:
        """Open a new session for a binary file.
        
        If the binary is already open, returns the existing session.
        Priority for getting a process:
        1. Reuse an idle process (process without active session)
        2. Start a new process if under max_processes limit
        3. Evict LRU session and reuse its process
        
        Args:
            binary_path: Path to the binary file
            run_auto_analysis: Whether to run IDA auto-analysis
            
        Returns:
            ProxySession for the opened binary
            
        Raises:
            FileNotFoundError: If binary file doesn't exist
            RuntimeError: If failed to open session
        """
        # Normalize path
        path = Path(binary_path).resolve()
        binary_path_str = str(path)
        
        if not path.exists():
            raise FileNotFoundError(f"Binary file not found: {binary_path}")
        
        with self._lock:
            # Check if already open
            if binary_path_str in self._binary_to_session:
                session_id = self._binary_to_session[binary_path_str]
                session = self._sessions[session_id]
                session.touch()
                self._update_lru(session_id)
                self._set_current(session_id)
                logger.info(f"Returning existing session: {session_id}")
                return session
            
            # Try to get a process port
            port = None
            started_new_process = False
            
            # Priority 1: Try to reuse an idle process
            idle_port = self._get_idle_port()
            if idle_port is not None:
                port = idle_port
                logger.info(f"Reusing idle process on port {port}")
            
            # Priority 2: Start a new process if under limit
            elif self.process_manager.process_count < self.max_processes:
                process_info = self.process_manager.start_process()
                port = process_info.port
                started_new_process = True
                logger.info(f"Started new process on port {port}")
            
            # Priority 3: Evict LRU and reuse its process
            else:
                logger.info(f"Max processes ({self.max_processes}) reached, evicting LRU for reuse")
                port = self._evict_lru_for_reuse()
                if port is None:
                    raise RuntimeError("No process available and cannot evict any session")
                logger.info(f"Reusing evicted process on port {port}")
            
            # Call idalib_open on the process
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "idalib_open",
                    "arguments": {
                        "input_path": binary_path_str,
                        "run_auto_analysis": run_auto_analysis,
                    }
                }
            }
            
            try:
                response = self.process_manager.forward_request(port, request)
            except Exception as e:
                # Clean up on failure (only if we started a new process)
                if started_new_process:
                    self.process_manager.stop_process(port)
                raise RuntimeError(f"Failed to open binary: {e}")
            
            # Extract session ID from response
            if "error" in response:
                if started_new_process:
                    self.process_manager.stop_process(port)
                raise RuntimeError(f"idalib_open failed: {response['error']}")
            
            result = response.get("result", {})
            if isinstance(result, dict) and "content" in result:
                # MCP tools/call response format
                content = result["content"]
                if isinstance(content, list) and len(content) > 0:
                    text_content = content[0].get("text", "{}")
                    result_data = json.loads(text_content)
                else:
                    result_data = {}
            else:
                result_data = result
            
            if not result_data.get("success"):
                if started_new_process:
                    self.process_manager.stop_process(port)
                error = result_data.get("error", "Unknown error")
                raise RuntimeError(f"idalib_open failed: {error}")
            
            session_data = result_data.get("session", {})
            ida_session_id = session_data.get("session_id", "unknown")
            
            # Create proxy session
            session = ProxySession.create(
                binary_path=binary_path_str,
                process_port=port,
                ida_session_id=ida_session_id,
            )
            
            # Update process info
            process_info = self.process_manager.get_process(port)
            if process_info:
                process_info.current_ida_session = ida_session_id
                process_info.binary_path = binary_path_str
            
            # Store session
            self._sessions[session.session_id] = session
            self._binary_to_session[binary_path_str] = session.session_id
            self._port_to_session[port] = session.session_id
            self._update_lru(session.session_id)
            self._set_current(session.session_id)
            
            logger.info(f"Created new session: {session.session_id} on port {port}")
            return session
    
    def close_session(self, session_id: str, terminate_process: bool = False) -> bool:
        """Close a session.
        
        By default, the process is kept running for reuse. Set terminate_process=True
        to also terminate the idalib-mcp process.
        
        Args:
            session_id: Session ID to close
            terminate_process: If True, also terminate the idalib-mcp process
            
        Returns:
            True if closed successfully, False if not found
        """
        with self._lock:
            session = self._sessions.pop(session_id, None)
            
            if session is None:
                logger.warning(f"Session not found: {session_id}")
                return False
            
            port = session.process_port
            
            # Remove from mappings
            self._binary_to_session.pop(session.binary_path, None)
            self._port_to_session.pop(port, None)
            
            if session_id in self._lru_order:
                self._lru_order.remove(session_id)
            
            # Update current session if needed
            if self._current_session_id == session_id:
                self._current_session_id = self._lru_order[-1] if self._lru_order else None
                if self._current_session_id and self._current_session_id in self._sessions:
                    self._sessions[self._current_session_id].is_current = True
            
            # Close the IDA session on the process
            try:
                request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "idalib_close",
                        "arguments": {
                            "session_id": session.ida_session_id,
                        }
                    }
                }
                self.process_manager.forward_request(port, request)
            except Exception as e:
                logger.warning(f"Failed to close IDA session: {e}")
            
            # Terminate the process if requested
            if terminate_process:
                self.process_manager.stop_process(port)
            
            logger.info(f"Closed session: {session_id}")
            return True
    
    def switch_session(self, session_id: str) -> ProxySession:
        """Switch to a different session.
        
        Args:
            session_id: Session ID to switch to
            
        Returns:
            The switched-to session
            
        Raises:
            ValueError: If session not found
        """
        with self._lock:
            session = self._sessions.get(session_id)
            
            if session is None:
                raise ValueError(f"Session not found: {session_id}")
            
            session.touch()
            self._update_lru(session_id)
            self._set_current(session_id)
            
            logger.info(f"Switched to session: {session_id}")
            return session
    
    def _set_current(self, session_id: str) -> None:
        """Set the current active session.
        
        Args:
            session_id: Session ID to set as current
        """
        # Clear previous current flag
        if self._current_session_id and self._current_session_id in self._sessions:
            self._sessions[self._current_session_id].is_current = False
        
        self._current_session_id = session_id
        
        if session_id in self._sessions:
            self._sessions[session_id].is_current = True
    
    def get_session(self, session_id: str) -> Optional[ProxySession]:
        """Get a session by ID.
        
        Args:
            session_id: Session ID to retrieve
            
        Returns:
            ProxySession or None if not found
        """
        with self._lock:
            return self._sessions.get(session_id)
    
    def get_current_session(self) -> Optional[ProxySession]:
        """Get the current active session.
        
        Returns:
            Current ProxySession or None if no active session
        """
        with self._lock:
            if self._current_session_id is None:
                return None
            return self._sessions.get(self._current_session_id)
    
    def list_sessions(self) -> List[Dict]:
        """List all active sessions.
        
        Returns:
            List of session dictionaries
        """
        with self._lock:
            return [session.to_dict() for session in self._sessions.values()]
    
    def get_session_by_binary(self, binary_path: str) -> Optional[ProxySession]:
        """Get session by binary path.
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            ProxySession or None if not found
        """
        path = Path(binary_path).resolve()
        binary_path_str = str(path)
        
        with self._lock:
            session_id = self._binary_to_session.get(binary_path_str)
            if session_id:
                return self._sessions.get(session_id)
            return None
    
    @property
    def session_count(self) -> int:
        """Get the number of active sessions."""
        with self._lock:
            return len(self._sessions)
    
    def close_all(self) -> None:
        """Close all sessions."""
        with self._lock:
            session_ids = list(self._sessions.keys())
        
        for session_id in session_ids:
            self.close_session(session_id)
