import argparse
import json
import logging
import random
import sys
import threading
import time
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class TestConfig:
    host: str = "127.0.0.1"
    port: int = 8744
    num_threads: int = 3
    requests_per_thread: int = 50
    test_files: List[str] = None # List of files to test

class MCPClient:
    def __init__(self, host: str, port: int):
        self.base_url = f"http://{host}:{port}/mcp"
        self.host = host
        self.port = port
        self._id_counter = 0
        self._lock = threading.Lock()

    def _get_id(self) -> int:
        with self._lock:
            self._id_counter += 1
            return self._id_counter

    def send_request(self, method: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Send a JSON-RPC request to the MCP server."""
        req_id = self._get_id()
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params or {}
        }
        
        start_time = time.time()
        conn = http.client.HTTPConnection(self.host, self.port, timeout=30)
        
        try:
            headers = {"Content-Type": "application/json"}
            conn.request("POST", "/mcp", json.dumps(payload), headers)
            response = conn.getresponse()
            data = response.read().decode()
            
            elapsed = time.time() - start_time
            
            if response.status != 200:
                logger.error(f"HTTP Error {response.status}: {data}")
                return {"error": {"code": response.status, "message": f"HTTP Error: {data}"}, "elapsed": elapsed}
                
            try:
                result = json.loads(data)
                result["elapsed"] = elapsed
                return result
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON response: {data}")
                return {"error": {"code": -32700, "message": "Parse error"}, "elapsed": elapsed}
                
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"Connection error: {e}")
            return {"error": {"code": -32000, "message": str(e)}, "elapsed": elapsed}
        finally:
            conn.close()

def run_worker(client: MCPClient, thread_id: int, config: TestConfig, target_file: str) -> Dict[str, Any]:
    """Worker function to simulate a user session."""
    stats = {
        "thread_id": thread_id,
        "success": 0,
        "errors": 0,
        "timeouts": 0,
        "max_latency": 0.0,
        "avg_latency": 0.0,
        "total_latency": 0.0
    }
    
    # 1. Open Session (idalib_open)
    logger.info(f"Thread {thread_id} opening session for file: {target_file}")
    
    open_args = {
        "name": "idalib_open",
        "arguments": {
            "input_path": target_file,
            "run_auto_analysis": False # Don't run long analysis for this quick test
        }
    }
    
    resp = client.send_request("tools/call", open_args)
    if "error" in resp:
        logger.error(f"Thread {thread_id} failed to open session: {resp['error']}")
        stats["errors"] += 1
        return stats
        
    # Extract session ID from nested result
    try:
        content = resp["result"].get("content", [])
        if content:
            result_data = json.loads(content[0]["text"])
            session_id = result_data.get("session", {}).get("session_id")
            if not session_id:
                raise ValueError("No session_id in response")
            logger.info(f"Thread {thread_id} got session: {session_id}")
        else:
            raise ValueError("Empty content in response")
    except Exception as e:
        logger.error(f"Thread {thread_id} failed to parse session ID: {e}")
        stats["errors"] += 1
        return stats

    # 2. Loop requests
    for i in range(config.requests_per_thread):
        # determine request type
        req_type = random.choice(["tools/list", "idalib_current", "tools/list"]) # Bias towards tools/list
        
        if req_type == "tools/list":
            method = "tools/list"
            params = {}
        elif req_type == "idalib_current":
            method = "tools/call"
            params = {"name": "idalib_current", "arguments": {}}
            
        # Send request
        resp = client.send_request(method, params)
        
        # Record stats
        latency = resp.get("elapsed", 0.0)
        stats["total_latency"] += latency
        stats["max_latency"] = max(stats["max_latency"], latency)
        
        if "error" in resp:
            logger.warning(f"Thread {thread_id} req {i} failed: {resp['error'].get('message')}")
            stats["errors"] += 1
        else:
            stats["success"] += 1
            
        # Small sleep to interleave requests
        time.sleep(random.uniform(0.05, 0.2))

    if stats["success"] > 0:
        stats["avg_latency"] = stats["total_latency"] / stats["success"]
        
    # 3. Cleanup
    close_args = {
        "name": "idalib_close",
        "arguments": {"session_id": session_id}
    }
    client.send_request("tools/call", close_args)
    
    return stats

def main():
    parser = argparse.ArgumentParser(description="Stress test IDA Pro Proxy MCP")
    parser.add_argument("--host", default="127.0.0.1", help="Proxy host")
    parser.add_argument("--port", type=int, default=8744, help="Proxy port")
    parser.add_argument("--threads", type=int, default=3, help="Number of concurrent threads")
    parser.add_argument("--count", type=int, default=20, help="Requests per thread")
    parser.add_argument("--file", default=None, help="Target file to open (optional)")
    
    args = parser.parse_args()
    
    # Determine test files
    import os
    test_files = []
    
    # Try to find samples directory relative to this script or current dir
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir) # Assuming tests/ is in project root
    samples_dir = os.path.join(project_root, "samples")
    
    if os.path.exists(samples_dir) and os.path.isdir(samples_dir):
        # Look for test1, test2, test3
        for fname in ["test1", "test2", "test3"]:
            fpath = os.path.join(samples_dir, fname)
            if os.path.exists(fpath):
                test_files.append(fpath)
                
    if not test_files and args.file:
        test_files = [args.file]
        
    if not test_files:
        # Fallback to script itself if nothing else found
        test_files = [os.path.abspath(__file__)]
        
    logger.info(f"Using test files: {test_files}")
    
    config = TestConfig(
        host=args.host,
        port=args.port,
        num_threads=args.threads,
        requests_per_thread=args.count,
        test_files=test_files
    )
    
    logger.info(f"Starting stress test with {config.num_threads} threads, {config.requests_per_thread} requests each")
    logger.info(f"Target: http://{config.host}:{config.port}/mcp")
    
    start_global = time.time()
    
    # Run threads
    failed_setup = False
    
    # First, verify connectivity
    client = MCPClient(config.host, config.port)
    init_resp = client.send_request("initialize", {
        "protocolVersion": "2024-11-05", 
        "capabilities": {}, 
        "clientInfo": {"name": "stress-test", "version": "1.0"}
    })
    
    if "error" in init_resp:
        logger.error("Failed to initialize with server. Is it running?")
        sys.exit(1)
    logger.info("Server initialized successfully.")

    futures = []
    with ThreadPoolExecutor(max_workers=config.num_threads) as executor:
        for i in range(config.num_threads):
            # Assign a file to this thread
            target = config.test_files[i % len(config.test_files)]
            
            thread_client = MCPClient(config.host, config.port)
            futures.append(executor.submit(run_worker, thread_client, i, config, target))
            
    # Aggregate results
    # ... (rest of main) ...
    total_reqs = 0
    total_errors = 0
    latencies = []
    
    for future in as_completed(futures):
        stats = future.result()
        total_reqs += stats["success"] + stats["errors"]
        total_errors += stats["errors"]
        if stats["avg_latency"] > 0:
            latencies.append(stats["avg_latency"])
        logger.info(f"Thread {stats['thread_id']} finished: {stats['success']} ok, {stats['errors']} err, avg {stats['avg_latency']:.4f}s")

    duration = time.time() - start_global
    
    print("\n" + "="*50)
    print("STRESS TEST RESULTS")
    print("="*50)
    print(f"Total Duration: {duration:.2f}s")
    print(f"Total Requests: {total_reqs}")
    print(f"Total Errors:   {total_errors}")
    print(f"Error Rate:     {(total_errors/total_reqs*100) if total_reqs else 0:.2f}%")
    if latencies:
        print(f"Avg Latency:    {sum(latencies)/len(latencies):.4f}s")
    else:
        print("Avg Latency:    N/A")
    print("="*50)

if __name__ == "__main__":
    main()
