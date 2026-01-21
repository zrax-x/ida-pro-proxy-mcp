"""Process Manager for idalib-mcp child processes"""

import json
import http.client
import logging
import subprocess
import threading
import time
from datetime import datetime
from typing import Dict, Optional, Set

from .models import ProcessInfo

logger = logging.getLogger(__name__)


class ProcessManager:
    """Manages idalib-mcp child processes.
    
    Handles starting, stopping, and communicating with idalib-mcp processes.
    Each process listens on a unique port starting from BASE_PORT.
    """
    
    BASE_PORT = 8745
    
    def __init__(self, host: str = "127.0.0.1", request_timeout: int = 30):
        """Initialize the process manager.
        
        Args:
            host: Host address for child processes
            request_timeout: Timeout for HTTP requests to child processes
        """
        self.host = host
        self.request_timeout = request_timeout
        self._processes: Dict[int, ProcessInfo] = {}  # port -> ProcessInfo
        self._available_ports: Set[int] = set()
        self._next_port = self.BASE_PORT
        self._lock = threading.RLock()
        self._default_port: Optional[int] = None  # Port of default process
    
    def check_existing_server(self, port: int) -> bool:
        """Check if an idalib-mcp server is already running on the given port.
        
        Args:
            port: Port to check
            
        Returns:
            True if server is responding, False otherwise
        """
        try:
            conn = http.client.HTTPConnection(self.host, port, timeout=2)
            test_request = json.dumps({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "health-check", "version": "1.0.0"}
                }
            })
            conn.request("POST", "/mcp", test_request, {"Content-Type": "application/json"})
            response = conn.getresponse()
            conn.close()
            return response.status == 200
        except Exception:
            return False
    
    def ensure_default_process(self, startup_timeout: int = 60) -> ProcessInfo:
        """Ensure a default idalib-mcp process is running.
        
        This checks if a server is already running on BASE_PORT.
        If not, it starts a new one without a binary file.
        
        Args:
            startup_timeout: Maximum time to wait for process to be ready
            
        Returns:
            ProcessInfo for the default process
        """
        with self._lock:
            # Check if we already have a default process
            if self._default_port and self._default_port in self._processes:
                info = self._processes[self._default_port]
                if info.is_alive():
                    return info
            
            # Check if there's an existing server on BASE_PORT
            if self.check_existing_server(self.BASE_PORT):
                logger.info(f"Found existing idalib-mcp server on port {self.BASE_PORT}")
                # Create a ProcessInfo for the external server (no process handle)
                info = ProcessInfo(
                    port=self.BASE_PORT,
                    pid=0,  # Unknown PID for external process
                    process=None,  # No process handle
                    binary_path="",
                )
                info._external = True  # Mark as external
                self._processes[self.BASE_PORT] = info
                self._default_port = self.BASE_PORT
                self._next_port = self.BASE_PORT + 1  # Skip this port
                return info
        
        # Start a new default process without binary
        logger.info("Starting default idalib-mcp process...")
        info = self.start_process(binary_path=None, startup_timeout=startup_timeout)
        self._default_port = info.port
        return info
    
    def get_default_port(self) -> Optional[int]:
        """Get the port of the default process.
        
        Returns:
            Port number or None if no default process
        """
        return self._default_port
    
    def allocate_port(self) -> int:
        """Allocate the next available port.
        
        Returns:
            Available port number
            
        Raises:
            RuntimeError: If no ports are available
        """
        with self._lock:
            # First try to reuse a released port
            if self._available_ports:
                return self._available_ports.pop()
            
            # Otherwise allocate a new port
            port = self._next_port
            self._next_port += 1
            return port
    
    def release_port(self, port: int) -> None:
        """Release a port for reuse.
        
        Args:
            port: Port number to release
        """
        with self._lock:
            self._available_ports.add(port)
    
    def start_process(self, binary_path: Optional[str] = None, startup_timeout: int = 60) -> ProcessInfo:
        """Start a new idalib-mcp process.
        
        Args:
            binary_path: Optional path to binary file to load initially
            startup_timeout: Maximum time to wait for process to be ready (seconds)
            
        Returns:
            ProcessInfo for the started process
            
        Raises:
            RuntimeError: If process fails to start
        """
        port = self.allocate_port()
        
        cmd = [
            "uv", "run", "idalib-mcp",
            "--host", self.host,
            "--port", str(port),
        ]
        
        if binary_path:
            cmd.append(binary_path)
        
        logger.info(f"Starting idalib-mcp on port {port}: {' '.join(cmd)}")
        
        try:
            # Don't use start_new_session - let child processes inherit our process group
            # This way, when proxy is killed via process group, children are also killed
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            
            # Wait for process to be ready by polling the HTTP endpoint
            start_time = time.time()
            ready = False
            last_error = None
            
            while time.time() - start_time < startup_timeout:
                # Check if process crashed
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    self.release_port(port)
                    raise RuntimeError(
                        f"idalib-mcp process exited immediately: {stderr.decode()}"
                    )
                
                # Try to connect to the HTTP endpoint
                try:
                    conn = http.client.HTTPConnection(self.host, port, timeout=2)
                    # Send a simple initialize request to check if server is ready
                    test_request = json.dumps({
                        "jsonrpc": "2.0",
                        "id": 0,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "health-check", "version": "1.0.0"}
                        }
                    })
                    conn.request("POST", "/mcp", test_request, {"Content-Type": "application/json"})
                    response = conn.getresponse()
                    if response.status == 200:
                        ready = True
                        logger.info(f"idalib-mcp on port {port} is ready (took {time.time() - start_time:.1f}s)")
                        break
                    conn.close()
                except (ConnectionRefusedError, OSError, http.client.HTTPException) as e:
                    last_error = e
                    time.sleep(0.5)  # Wait before retrying
                    continue
            
            if not ready:
                # Cleanup on timeout
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                self.release_port(port)
                raise RuntimeError(
                    f"idalib-mcp on port {port} failed to become ready within {startup_timeout}s. "
                    f"Last error: {last_error}"
                )
            
            info = ProcessInfo(
                port=port,
                pid=process.pid,
                process=process,
                binary_path=binary_path or "",
            )
            
            with self._lock:
                self._processes[port] = info
            
            logger.info(f"Started idalib-mcp process (pid={process.pid}, port={port})")
            return info
            
        except FileNotFoundError as e:
            self.release_port(port)
            raise RuntimeError(f"Failed to start idalib-mcp: {e}")
        except RuntimeError:
            raise
        except Exception as e:
            self.release_port(port)
            raise RuntimeError(f"Failed to start idalib-mcp: {e}")
    
    def stop_process(self, port: int) -> bool:
        """Stop a process by port.
        
        Args:
            port: Port of the process to stop
            
        Returns:
            True if process was stopped, False if not found
        """
        with self._lock:
            info = self._processes.pop(port, None)
            
        if info is None:
            logger.warning(f"No process found on port {port}")
            return False
        
        # Don't terminate external processes
        if getattr(info, '_external', False):
            logger.info(f"Skipping termination of external process on port {port}")
            return True
        
        logger.info(f"Stopping idalib-mcp process (pid={info.pid}, port={port})")
        info.terminate()
        self.release_port(port)
        
        return True
    
    def stop_all(self) -> None:
        """Stop all managed processes."""
        with self._lock:
            ports = list(self._processes.keys())
        
        logger.info(f"Stopping all {len(ports)} idalib-mcp processes")
        
        for port in ports:
            self.stop_process(port)
        
        logger.info("All processes stopped")
    
    def get_process(self, port: int) -> Optional[ProcessInfo]:
        """Get process info by port.
        
        Args:
            port: Port number
            
        Returns:
            ProcessInfo or None if not found
        """
        with self._lock:
            return self._processes.get(port)
    
    def check_process_health(self, port: int) -> bool:
        """Check if a process is healthy.
        
        Args:
            port: Port of the process to check
            
        Returns:
            True if process is alive and responding
        """
        with self._lock:
            info = self._processes.get(port)
        
        if info is None:
            return False
        
        return info.is_alive()
    
    def forward_request(self, port: int, request: dict, timeout: Optional[int] = None) -> dict:
        """Forward a JSON-RPC request to a child process.
        
        Args:
            port: Port of the target process
            request: JSON-RPC request dictionary
            timeout: Optional timeout override (seconds)
            
        Returns:
            JSON-RPC response dictionary
            
        Raises:
            RuntimeError: If request fails
        """
        # Check process health first
        if not self.check_process_health(port):
            raise RuntimeError(f"Process on port {port} is not healthy")
        
        request_timeout = timeout if timeout is not None else self.request_timeout
        conn = http.client.HTTPConnection(
            self.host, port, timeout=request_timeout
        )
        
        try:
            body = json.dumps(request)
            conn.request("POST", "/mcp", body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            data = response.read().decode()
            return json.loads(data)
        except Exception as e:
            method = request.get("method", "unknown")
            logger.error(f"Request '{method}' to port {port} failed: {e}")
            raise RuntimeError(f"Request to port {port} failed: {e}")
        finally:
            conn.close()
    
    @property
    def process_count(self) -> int:
        """Get the number of active processes."""
        with self._lock:
            return len(self._processes)
    
    @property
    def active_ports(self) -> list[int]:
        """Get list of active ports."""
        with self._lock:
            return list(self._processes.keys())
