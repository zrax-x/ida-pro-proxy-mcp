"""
End-to-End Integration Test for IDA Pro Proxy MCP

This test:
1. Starts the IDA Pro Proxy MCP server with max_processes=2
2. Performs MCP initialize handshake
3. Opens first binary and calls decompile
4. Opens second binary and calls decompile
5. Opens third binary (triggers LRU eviction)
6. Verifies session management and tool routing

Usage:
    python -m pytest tests/test_e2e_integration.py -v -s

Note: This test requires idalib-mcp to be installed and IDA Pro license available.
"""

import json
import time
import http.client
import subprocess
import signal
import os
import sys
from pathlib import Path

import pytest

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Sample binaries path (relative to workspace root)
WORKSPACE_ROOT = Path(__file__).parent.parent.parent
SAMPLES_DIR = WORKSPACE_ROOT / "samples"

# Test configuration
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8744
MAX_PROCESSES = 2


class McpClient:
    """Simple MCP client for testing"""
    
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._request_id = 0
    
    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id
    
    def send_request(self, method: str, params: dict = None) -> dict:
        """Send a JSON-RPC request to the MCP server"""
        request = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
            "params": params or {}
        }
        
        conn = http.client.HTTPConnection(self.host, self.port, timeout=120)
        try:
            body = json.dumps(request)
            conn.request("POST", "/mcp", body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            data = response.read().decode()
            return json.loads(data)
        finally:
            conn.close()
    
    def initialize(self) -> dict:
        """Perform MCP initialize handshake"""
        return self.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        })
    
    def list_tools(self) -> dict:
        """List available tools"""
        return self.send_request("tools/list", {})
    
    def call_tool(self, name: str, arguments: dict) -> dict:
        """Call a tool"""
        return self.send_request("tools/call", {
            "name": name,
            "arguments": arguments
        })
    
    def idalib_open(self, binary_path: str, run_auto_analysis: bool = True) -> dict:
        """Open a binary file"""
        return self.call_tool("idalib_open", {
            "input_path": binary_path,
            "run_auto_analysis": run_auto_analysis
        })
    
    def idalib_list(self) -> dict:
        """List all sessions"""
        return self.call_tool("idalib_list", {})
    
    def idalib_current(self) -> dict:
        """Get current session"""
        return self.call_tool("idalib_current", {})
    
    def idalib_switch(self, session_id: str) -> dict:
        """Switch to a session"""
        return self.call_tool("idalib_switch", {"session_id": session_id})
    
    def idalib_close(self, session_id: str) -> dict:
        """Close a session"""
        return self.call_tool("idalib_close", {"session_id": session_id})
    
    def decompile(self, addr: str, session: str = None) -> dict:
        """Decompile a function"""
        args = {"addr": addr}
        if session:
            args["session"] = session
        return self.call_tool("decompile", args)
    
    def list_funcs(self, filter_pattern: str = "*", session: str = None) -> dict:
        """List functions"""
        args = {"queries": filter_pattern}
        if session:
            args["session"] = session
        return self.call_tool("list_funcs", args)


def parse_tool_result(response: dict) -> dict:
    """Parse tool result from MCP response"""
    if "error" in response:
        return {"error": response["error"]}
    
    result = response.get("result", {})
    content = result.get("content", [])
    
    if content and len(content) > 0:
        text = content[0].get("text", "{}")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"text": text}
    
    return result


@pytest.fixture(scope="module")
def proxy_server():
    """Start the proxy server for testing"""
    # Get the src directory path
    src_dir = Path(__file__).parent.parent / "src"
    
    # Start the server process using -m to support relative imports
    env = os.environ.copy()
    env["PYTHONPATH"] = str(src_dir)
    
    process = subprocess.Popen(
        [
            sys.executable,
            "-m", "ida_pro_proxy_mcp.server",
            "--host", PROXY_HOST,
            "--port", str(PROXY_PORT),
            "--max-processes", str(MAX_PROCESSES),
            "--verbose"
        ],
        env=env,
        cwd=str(src_dir),  # Set working directory to src
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    
    # Wait for server to start
    time.sleep(2)
    
    # Check if server started successfully
    if process.poll() is not None:
        stdout, stderr = process.communicate()
        pytest.fail(f"Server failed to start:\nstdout: {stdout.decode()}\nstderr: {stderr.decode()}")
    
    yield process
    
    # Cleanup: stop the server
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


@pytest.fixture
def client():
    """Create an MCP client"""
    return McpClient(PROXY_HOST, PROXY_PORT)


class TestE2EIntegration:
    """End-to-end integration tests"""
    
    @pytest.mark.skipif(
        not (SAMPLES_DIR / "login").exists(),
        reason="Sample binaries not found"
    )
    def test_full_workflow(self, proxy_server, client):
        """
        Test the full workflow:
        1. Initialize
        2. Open binary 1, decompile
        3. Open binary 2, decompile
        4. Open binary 3 (triggers LRU eviction)
        5. Verify session management
        """
        # Step 1: Initialize
        print("\n=== Step 1: Initialize ===")
        response = client.initialize()
        assert "result" in response, f"Initialize failed: {response}"
        assert response["result"]["serverInfo"]["name"] == "ida-pro-proxy-mcp"
        print(f"Server info: {response['result']['serverInfo']}")
        
        # Step 2: List tools
        print("\n=== Step 2: List Tools ===")
        response = client.list_tools()
        assert "result" in response, f"List tools failed: {response}"
        tools = response["result"].get("tools", [])
        print(f"Available tools: {len(tools)}")
        
        # Step 3: Open first binary (login)
        print("\n=== Step 3: Open Binary 1 (login) ===")
        binary1 = str(SAMPLES_DIR / "login")
        response = client.idalib_open(binary1)
        result1 = parse_tool_result(response)
        
        if "error" in result1:
            pytest.skip(f"idalib_open failed (IDA not available?): {result1['error']}")
        
        assert result1.get("success"), f"Open binary 1 failed: {result1}"
        session1_id = result1["session"]["session_id"]
        print(f"Session 1: {session1_id}")
        
        # Step 4: List functions in binary 1
        print("\n=== Step 4: List Functions (Binary 1) ===")
        response = client.list_funcs("main")
        result = parse_tool_result(response)
        print(f"Functions found: {result}")
        
        # Step 5: Decompile main function
        print("\n=== Step 5: Decompile main (Binary 1) ===")
        response = client.decompile("main")
        result = parse_tool_result(response)
        if "error" not in result:
            print(f"Decompile result: {result.get('code', 'N/A')[:200]}...")
        else:
            print(f"Decompile error: {result['error']}")
        
        # Step 6: Open second binary (magic)
        print("\n=== Step 6: Open Binary 2 (magic) ===")
        binary2 = str(SAMPLES_DIR / "magic")
        response = client.idalib_open(binary2)
        result2 = parse_tool_result(response)
        assert result2.get("success"), f"Open binary 2 failed: {result2}"
        session2_id = result2["session"]["session_id"]
        print(f"Session 2: {session2_id}")
        
        # Step 7: List sessions (should have 2)
        print("\n=== Step 7: List Sessions ===")
        response = client.idalib_list()
        result = parse_tool_result(response)
        assert result["count"] == 2, f"Expected 2 sessions, got {result['count']}"
        print(f"Sessions: {[s['session_id'] for s in result['sessions']]}")
        
        # Step 8: Decompile in binary 2
        print("\n=== Step 8: Decompile main (Binary 2) ===")
        response = client.decompile("main", session=session2_id)
        result = parse_tool_result(response)
        if "error" not in result:
            print(f"Decompile result: {result.get('code', 'N/A')[:200]}...")
        
        # Step 9: Open third binary (pwn) - should trigger LRU eviction
        print("\n=== Step 9: Open Binary 3 (pwn) - LRU Eviction ===")
        binary3 = str(SAMPLES_DIR / "pwn")
        response = client.idalib_open(binary3)
        result3 = parse_tool_result(response)
        assert result3.get("success"), f"Open binary 3 failed: {result3}"
        session3_id = result3["session"]["session_id"]
        print(f"Session 3: {session3_id}")
        
        # Step 10: Verify LRU eviction
        print("\n=== Step 10: Verify LRU Eviction ===")
        response = client.idalib_list()
        result = parse_tool_result(response)
        assert result["count"] == 2, f"Expected 2 sessions after eviction, got {result['count']}"
        
        session_ids = [s["session_id"] for s in result["sessions"]]
        print(f"Remaining sessions: {session_ids}")
        
        # Session 1 should be evicted (LRU)
        assert session1_id not in session_ids, "Session 1 should have been evicted"
        assert session2_id in session_ids, "Session 2 should still exist"
        assert session3_id in session_ids, "Session 3 should exist"
        
        # Step 11: Switch to session 2 and decompile
        print("\n=== Step 11: Switch to Session 2 ===")
        response = client.idalib_switch(session2_id)
        result = parse_tool_result(response)
        assert result.get("success"), f"Switch failed: {result}"
        
        # Step 12: Verify current session
        print("\n=== Step 12: Verify Current Session ===")
        response = client.idalib_current()
        result = parse_tool_result(response)
        assert result["session_id"] == session2_id
        print(f"Current session: {result['session_id']}")
        
        # Step 13: Close session 3
        print("\n=== Step 13: Close Session 3 ===")
        response = client.idalib_close(session3_id)
        result = parse_tool_result(response)
        assert result.get("success"), f"Close failed: {result}"
        
        # Step 14: Final session list
        print("\n=== Step 14: Final Session List ===")
        response = client.idalib_list()
        result = parse_tool_result(response)
        assert result["count"] == 1, f"Expected 1 session, got {result['count']}"
        print(f"Final sessions: {[s['session_id'] for s in result['sessions']]}")
        
        print("\n=== All Tests Passed! ===")


class TestWithoutServer:
    """Tests that don't require the actual server"""
    
    def test_sample_binaries_exist(self):
        """Verify sample binaries exist"""
        assert (SAMPLES_DIR / "login").exists(), "login binary not found"
        assert (SAMPLES_DIR / "magic").exists(), "magic binary not found"
        assert (SAMPLES_DIR / "pwn").exists(), "pwn binary not found"
    
    def test_mcp_client_creation(self):
        """Test MCP client can be created"""
        client = McpClient("127.0.0.1", 8744)
        assert client.host == "127.0.0.1"
        assert client.port == 8744


if __name__ == "__main__":
    # Run as standalone script for manual testing
    print("Starting IDA Pro Proxy MCP E2E Test")
    print(f"Samples directory: {SAMPLES_DIR}")
    print(f"Proxy: {PROXY_HOST}:{PROXY_PORT}")
    print(f"Max processes: {MAX_PROCESSES}")
    
    # Check if server is already running
    client = McpClient(PROXY_HOST, PROXY_PORT)
    
    try:
        response = client.initialize()
        print(f"\nServer already running: {response}")
    except Exception as e:
        print(f"\nServer not running, please start it first:")
        print(f"  python -m ida_pro_proxy_mcp.server --host {PROXY_HOST} --port {PROXY_PORT} --max-processes {MAX_PROCESSES}")
        sys.exit(1)
    
    # Run the test
    test = TestE2EIntegration()
    test.test_full_workflow(None, client)
