"""Core data models for IDA Pro Proxy MCP"""

import os
import signal
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class ProxySession:
    """Represents a proxy session mapping to an idalib-mcp process.
    
    Attributes:
        session_id: Unique session ID in format [binary-name]-[ida-session-id]
        binary_path: Full path to the binary file
        binary_name: Name of the binary file (extracted from path)
        process_port: Port of the corresponding idalib-mcp process
        ida_session_id: Original session ID returned by idalib-mcp
        created_at: Session creation timestamp
        last_accessed: Last access timestamp (for LRU tracking)
        is_current: Whether this is the current active session
    """
    session_id: str
    binary_path: str
    binary_name: str
    process_port: int
    ida_session_id: str
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    is_current: bool = False
    
    @classmethod
    def create(cls, binary_path: str, process_port: int, ida_session_id: str) -> "ProxySession":
        """Create a new ProxySession with auto-generated session_id.
        
        Args:
            binary_path: Path to the binary file
            process_port: Port of the idalib-mcp process
            ida_session_id: Session ID returned by idalib-mcp
            
        Returns:
            New ProxySession instance
        """
        path = Path(binary_path)
        binary_name = path.name
        session_id = f"{binary_name}-{ida_session_id}"
        
        return cls(
            session_id=session_id,
            binary_path=str(path.resolve()),
            binary_name=binary_name,
            process_port=process_port,
            ida_session_id=ida_session_id,
        )
    
    def touch(self) -> None:
        """Update last_accessed timestamp."""
        self.last_accessed = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary format for JSON serialization."""
        return {
            "session_id": self.session_id,
            "binary_path": self.binary_path,
            "binary_name": self.binary_name,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "is_current": self.is_current,
        }


@dataclass
class ProcessInfo:
    """Information about a managed idalib-mcp process.
    
    Attributes:
        port: Port the process is listening on
        pid: Process ID
        process: Subprocess object for the running process (None for external processes)
        binary_path: Path to the binary file loaded in this process
        started_at: Process start timestamp
        current_ida_session: Current IDA session ID in this process
    """
    port: int
    pid: int
    process: Optional[subprocess.Popen]
    binary_path: str
    started_at: datetime = field(default_factory=datetime.now)
    current_ida_session: Optional[str] = None
    _external: bool = field(default=False, repr=False)  # True if external process
    
    def is_alive(self) -> bool:
        """Check if the process is still running."""
        if self._external:
            # For external processes, we can't check directly
            # Assume alive (health check will verify)
            return True
        if self.process is None:
            return False
        return self.process.poll() is None
    
    def terminate(self) -> None:
        """Terminate the process gracefully, including all child processes.
        
        Uses platform-specific approaches to terminate processes.
        """
        if self._external:
            # Don't terminate external processes
            return
        if self.process is None or not self.is_alive():
            return
        
        pid = self.process.pid
        
        import platform
        is_windows = platform.system() == "Windows"
        
        try:
            if is_windows:
                # Windows: Use process.terminate() which sends CTRL_BREAK_EVENT
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if not terminated
                    self.process.kill()
                    self.process.wait()
            else:
                # Unix: Try to find and kill all child processes first
                child_pids = self._get_child_pids(pid)
                
                # Send SIGTERM to main process first
                os.kill(pid, signal.SIGTERM)
                
                # Send SIGTERM to all children
                for child_pid in child_pids:
                    try:
                        os.kill(child_pid, signal.SIGTERM)
                    except (ProcessLookupError, OSError):
                        pass
                
                # Wait for main process
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if not terminated
                    os.kill(pid, signal.SIGKILL)
                    for child_pid in child_pids:
                        try:
                            os.kill(child_pid, signal.SIGKILL)
                        except (ProcessLookupError, OSError):
                            pass
                    self.process.wait()
                
        except (ProcessLookupError, OSError):
            # Process already terminated
            try:
                self.process.wait(timeout=1)
            except Exception:
                pass
    
    def _get_child_pids(self, parent_pid: int) -> list:
        """Get all child PIDs of a process by reading /proc.
        
        Args:
            parent_pid: Parent process ID
            
        Returns:
            List of child PIDs
        """
        child_pids = []
        try:
            # Read /proc to find children
            import os as os_module
            for entry in os_module.listdir('/proc'):
                if not entry.isdigit():
                    continue
                try:
                    with open(f'/proc/{entry}/stat', 'r') as f:
                        stat = f.read().split()
                        # stat[3] is the parent PID
                        if len(stat) > 3 and int(stat[3]) == parent_pid:
                            child_pids.append(int(entry))
                except (FileNotFoundError, PermissionError, ValueError):
                    continue
        except Exception:
            pass
        return child_pids


@dataclass
class ProxyConfig:
    """Configuration for the proxy server.
    
    Attributes:
        host: Host address to bind to
        port: Port for the proxy server
        max_processes: Maximum number of concurrent idalib-mcp processes
        base_port: Starting port for idalib-mcp processes
        request_timeout: Timeout for requests to child processes (seconds)
    """
    host: str = "127.0.0.1"
    port: int = 8744
    max_processes: int = 2
    base_port: int = 8745
    request_timeout: int = 300
    
    def validate(self) -> None:
        """Validate configuration values.
        
        Raises:
            ValueError: If configuration is invalid
        """
        if self.max_processes < 1:
            raise ValueError("max_processes must be at least 1")
        if self.port < 1 or self.port > 65535:
            raise ValueError("port must be between 1 and 65535")
        if self.base_port < 1 or self.base_port > 65535:
            raise ValueError("base_port must be between 1 and 65535")
        if self.request_timeout < 1:
            raise ValueError("request_timeout must be at least 1 second")
