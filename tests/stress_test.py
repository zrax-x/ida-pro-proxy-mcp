import argparse
import json
import logging
import random
import sys
import threading
import time
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
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
    test_files: List[str] = None  # List of files to test
    mode: str = "basic"  # "basic" or "decompile"
    run_auto_analysis: bool = True  # Whether to run IDA auto-analysis
    decompile_timeout: int = 60  # Timeout for each decompile call (seconds)

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

    def send_request(self, method: str, params: Optional[Dict] = None, timeout: int = 120) -> Dict[str, Any]:
        """Send a JSON-RPC request to the MCP server."""
        req_id = self._get_id()
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params or {}
        }
        
        start_time = time.time()
        conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        
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
    
    def call_tool(self, name: str, arguments: Dict[str, Any], timeout: int = 120) -> Dict[str, Any]:
        """Convenience method to call a tool."""
        return self.send_request("tools/call", {"name": name, "arguments": arguments}, timeout=timeout)
    
    def parse_tool_result(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse tool result from MCP response."""
        if "error" in response:
            return {"error": response["error"], "elapsed": response.get("elapsed", 0)}
        
        result = response.get("result", {})
        content = result.get("content", [])
        elapsed = response.get("elapsed", 0)
        
        if content and len(content) > 0:
            text = content[0].get("text", "{}")
            try:
                parsed = json.loads(text)
                # Handle both dict and list responses
                if isinstance(parsed, dict):
                    parsed["elapsed"] = elapsed
                    return parsed
                elif isinstance(parsed, list):
                    # Wrap list in a dict with elapsed time
                    return {"data": parsed, "elapsed": elapsed}
                else:
                    return {"value": parsed, "elapsed": elapsed}
            except json.JSONDecodeError:
                return {"text": text, "elapsed": elapsed}
        
        if isinstance(result, dict):
            result["elapsed"] = elapsed
        return result

def get_function_list(client: MCPClient, session_id: str = None) -> List[Dict[str, Any]]:
    """Get list of functions from the current binary."""
    args = {"queries": "*"}
    if session_id:
        args["session"] = session_id
    
    # Use longer timeout for large binaries - list_funcs can take a while
    resp = client.call_tool("list_funcs", args, timeout=180)
    result = client.parse_tool_result(resp)
    
    if "error" in result:
        logger.error(f"Failed to get function list: {result['error']}")
        return []
    
    # Debug: log raw response structure
    logger.debug(f"list_funcs response keys: {list(result.keys()) if isinstance(result, dict) else 'not a dict'}")
    
    # Parse the function list from the response
    # The response format from list_funcs is typically:
    # [{"query": "...", "data": [{"name": "func1", "addr": "0x1234"}, ...]}]
    # After parse_tool_result wraps lists, it becomes:
    # {"data": [{"query": "...", "data": [...]}, ...], "elapsed": ...}
    
    functions = []
    data = result.get("data", [])
    
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                # Check if this is a query result with nested data
                if "data" in item:
                    nested_data = item.get("data", [])
                    for func in nested_data:
                        if isinstance(func, dict) and func.get("addr") and func.get("name"):
                            functions.append({
                                "addr": func["addr"],
                                "name": func["name"]
                            })
                # Or if this is a direct function entry
                elif item.get("addr") and item.get("name"):
                    functions.append({
                        "addr": item["addr"],
                        "name": item["name"]
                    })
    
    # Also check for "functions" key (alternative format)
    if not functions and "functions" in result:
        for func in result.get("functions", []):
            if isinstance(func, dict) and func.get("addr") and func.get("name"):
                functions.append({
                    "addr": func["addr"],
                    "name": func["name"]
                })
    
    logger.info(f"Found {len(functions)} functions")
    if not functions:
        logger.debug(f"No functions found. Result structure: {json.dumps(result, indent=2)[:500]}")
    
    return functions


def run_worker_basic(client: MCPClient, thread_id: int, config: TestConfig, target_file: str) -> Dict[str, Any]:
    """Worker function for basic stress test (original behavior)."""
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
            "run_auto_analysis": config.run_auto_analysis
        }
    }
    
    resp = client.send_request("tools/call", open_args, timeout=300)
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
        req_type = random.choice(["tools/list", "idalib_current", "tools/list"])  # Bias towards tools/list
        
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


def run_worker_decompile(client: MCPClient, thread_id: int, config: TestConfig, target_file: str) -> Dict[str, Any]:
    """Worker function for decompile stress test."""
    stats = {
        "thread_id": thread_id,
        "success": 0,
        "errors": 0,
        "decompile_success": 0,
        "decompile_errors": 0,
        "timeouts": 0,
        "max_latency": 0.0,
        "avg_latency": 0.0,
        "total_latency": 0.0,
        "decompile_latencies": []
    }
    
    # 1. Open Session (idalib_open)
    logger.info(f"Thread {thread_id} opening session for file: {target_file}")
    
    resp = client.call_tool("idalib_open", {
        "input_path": target_file,
        "run_auto_analysis": config.run_auto_analysis
    }, timeout=300)
    
    result = client.parse_tool_result(resp)
    if "error" in result:
        logger.error(f"Thread {thread_id} failed to open session: {result['error']}")
        stats["errors"] += 1
        return stats
    
    session_id = result.get("session", {}).get("session_id")
    if not session_id:
        logger.error(f"Thread {thread_id} no session_id in response")
        stats["errors"] += 1
        return stats
    
    logger.info(f"Thread {thread_id} got session: {session_id}")
    stats["success"] += 1
    
    # 2. Get function list
    logger.info(f"Thread {thread_id} fetching function list...")
    functions = get_function_list(client, session_id)
    
    if not functions:
        logger.error(f"Thread {thread_id} failed to get function list")
        stats["errors"] += 1
        # Cleanup and return
        client.call_tool("idalib_close", {"session_id": session_id})
        return stats
    
    stats["success"] += 1
    
    # 3. Randomly select functions to decompile
    num_to_decompile = min(config.requests_per_thread, len(functions))
    selected_functions = random.sample(functions, num_to_decompile)
    
    logger.info(f"Thread {thread_id} will decompile {num_to_decompile} functions")
    
    # 4. Decompile loop
    for i, func in enumerate(selected_functions):
        func_addr = func["addr"]
        func_name = func["name"]
        
        logger.debug(f"Thread {thread_id} decompiling {func_name} @ {func_addr} ({i+1}/{num_to_decompile})")
        
        resp = client.call_tool("decompile", {
            "addr": func_addr,
            "session": session_id
        }, timeout=config.decompile_timeout)
        
        result = client.parse_tool_result(resp)
        latency = result.get("elapsed", resp.get("elapsed", 0.0))
        
        stats["total_latency"] += latency
        stats["max_latency"] = max(stats["max_latency"], latency)
        stats["decompile_latencies"].append(latency)
        
        if "error" in result:
            logger.warning(f"Thread {thread_id} decompile {func_name} failed: {result['error']}")
            stats["decompile_errors"] += 1
            stats["errors"] += 1
        elif result.get("code"):
            code_len = len(result.get("code", ""))
            logger.debug(f"Thread {thread_id} decompiled {func_name}: {code_len} chars")
            stats["decompile_success"] += 1
            stats["success"] += 1
        else:
            # No code but no error - possibly empty function
            logger.debug(f"Thread {thread_id} decompiled {func_name}: empty result")
            stats["decompile_success"] += 1
            stats["success"] += 1
        
        # Small random delay to simulate realistic usage
        time.sleep(random.uniform(0.1, 0.5))
    
    # Calculate average latency
    total_ops = stats["success"] + stats["errors"]
    if total_ops > 0:
        stats["avg_latency"] = stats["total_latency"] / total_ops
    
    # Calculate decompile-specific stats
    if stats["decompile_latencies"]:
        stats["avg_decompile_latency"] = sum(stats["decompile_latencies"]) / len(stats["decompile_latencies"])
        stats["max_decompile_latency"] = max(stats["decompile_latencies"])
        stats["min_decompile_latency"] = min(stats["decompile_latencies"])
    
    # 5. Cleanup
    logger.info(f"Thread {thread_id} closing session...")
    client.call_tool("idalib_close", {"session_id": session_id})
    
    return stats


def run_worker(client: MCPClient, thread_id: int, config: TestConfig, target_file: str) -> Dict[str, Any]:
    """Worker function that dispatches to the appropriate test mode."""
    if config.mode == "decompile":
        return run_worker_decompile(client, thread_id, config, target_file)
    else:
        return run_worker_basic(client, thread_id, config, target_file)

def main():
    parser = argparse.ArgumentParser(description="Stress test IDA Pro Proxy MCP")
    parser.add_argument("--host", default="127.0.0.1", help="Proxy host")
    parser.add_argument("--port", type=int, default=8744, help="Proxy port")
    parser.add_argument("--threads", type=int, default=4, help="Number of concurrent threads")
    parser.add_argument("--count", type=int, default=50, help="Requests/decompiles per thread")
    parser.add_argument("--file", default=None, help="Target file to open (optional)")
    parser.add_argument("--mode", choices=["basic", "decompile"], default="basic",
                        help="Test mode: 'basic' for simple requests, 'decompile' for decompilation stress test")
    parser.add_argument("--no-analysis", action="store_true", 
                        help="Skip IDA auto-analysis (faster open, but may have fewer recognized functions)")
    parser.add_argument("--max-processes", type=int, default=4,
                        help="Max processes on the proxy server (to prevent LRU eviction during decompile test)")
    parser.add_argument("--decompile-timeout", type=int, default=60,
                        help="Timeout in seconds for each decompile call (default: 60, increase for complex functions)")
    parser.add_argument("--sequential", action="store_true",
                        help="Open sessions sequentially (wait for each to complete before starting next)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Check threads vs max-processes for decompile mode
    num_threads = args.threads
    if args.mode == "decompile" and num_threads > args.max_processes:
        logger.warning(f"WARNING: threads ({num_threads}) > max-processes ({args.max_processes})")
        logger.warning("In decompile mode, this will cause LRU eviction of earlier sessions!")
        logger.warning(f"Limiting threads to {args.max_processes} to prevent session eviction.")
        logger.warning(f"Use --max-processes to match your proxy's --max-processes setting.")
        num_threads = args.max_processes
    
    # Determine test files
    import os
    test_files = []
    
    # Try to find samples directory relative to this script or current dir
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)  # Assuming tests/ is in project root
    samples_dir = os.path.join(project_root, "samples")
    
    if os.path.exists(samples_dir) and os.path.isdir(samples_dir):
        # Look for test samples
        for fname in ["3ed4c555080f9944791218f4d37140cb553d6bd2270fa2ebc99523aac105267d", "libvcm.so", "fsm-phMonitor-727", "phMonitor726"]:
            fpath = os.path.join(samples_dir, fname)
            if os.path.exists(fpath):
                test_files.append(fpath)
                
    if not test_files and args.file:
        test_files = [args.file]
        
    if not test_files:
        logger.error("No test files found. Please specify --file or add samples to the samples/ directory.")
        sys.exit(1)
        
    logger.info(f"Using test files: {test_files}")
    
    config = TestConfig(
        host=args.host,
        port=args.port,
        num_threads=num_threads,
        requests_per_thread=args.count,
        test_files=test_files,
        mode=args.mode,
        run_auto_analysis=not args.no_analysis,
        decompile_timeout=args.decompile_timeout
    )
    
    logger.info(f"Starting stress test with {config.num_threads} threads, {config.requests_per_thread} requests each")
    logger.info(f"Mode: {config.mode}, Auto-analysis: {config.run_auto_analysis}")
    if config.mode == "decompile":
        logger.info(f"Decompile timeout: {config.decompile_timeout}s")
    logger.info(f"Target: http://{config.host}:{config.port}/mcp")
    
    start_global = time.time()
    
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
    total_reqs = 0
    total_errors = 0
    latencies = []
    all_stats = []
    
    # Decompile-specific aggregates
    total_decompile_success = 0
    total_decompile_errors = 0
    decompile_latencies = []
    
    for future in as_completed(futures):
        stats = future.result()
        all_stats.append(stats)
        total_reqs += stats["success"] + stats["errors"]
        total_errors += stats["errors"]
        if stats["avg_latency"] > 0:
            latencies.append(stats["avg_latency"])
        
        # Collect decompile stats if available
        if "decompile_success" in stats:
            total_decompile_success += stats.get("decompile_success", 0)
            total_decompile_errors += stats.get("decompile_errors", 0)
            decompile_latencies.extend(stats.get("decompile_latencies", []))
            
            logger.info(f"Thread {stats['thread_id']} finished: {stats['decompile_success']} decompiled, "
                       f"{stats['decompile_errors']} failed, avg {stats.get('avg_decompile_latency', 0):.4f}s")
        else:
            logger.info(f"Thread {stats['thread_id']} finished: {stats['success']} ok, {stats['errors']} err, avg {stats['avg_latency']:.4f}s")

    duration = time.time() - start_global
    
    print("\n" + "="*60)
    print(f"STRESS TEST RESULTS ({config.mode.upper()} MODE)")
    print("="*60)
    print(f"Total Duration:     {duration:.2f}s")
    print(f"Threads:            {config.num_threads}")
    print(f"Requests/Thread:    {config.requests_per_thread}")
    print(f"Auto-Analysis:      {config.run_auto_analysis}")
    print("-"*60)
    print(f"Total Operations:   {total_reqs}")
    print(f"Total Errors:       {total_errors}")
    print(f"Error Rate:         {(total_errors/total_reqs*100) if total_reqs else 0:.2f}%")
    
    if latencies:
        print(f"Avg Latency:        {sum(latencies)/len(latencies):.4f}s")
    else:
        print("Avg Latency:        N/A")
    
    # Show decompile-specific stats if in decompile mode
    if config.mode == "decompile" and decompile_latencies:
        print("-"*60)
        print("DECOMPILE STATISTICS:")
        print(f"  Total Decompiled: {total_decompile_success}")
        print(f"  Failed:           {total_decompile_errors}")
        print(f"  Success Rate:     {(total_decompile_success/(total_decompile_success+total_decompile_errors)*100) if (total_decompile_success+total_decompile_errors) else 0:.2f}%")
        print(f"  Avg Latency:      {sum(decompile_latencies)/len(decompile_latencies):.4f}s")
        print(f"  Min Latency:      {min(decompile_latencies):.4f}s")
        print(f"  Max Latency:      {max(decompile_latencies):.4f}s")
        print(f"  Throughput:       {len(decompile_latencies)/duration:.2f} decompiles/sec")
    
    print("="*60)

if __name__ == "__main__":
    main()

