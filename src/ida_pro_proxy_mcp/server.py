"""HTTP Server for IDA Pro Proxy MCP"""

import argparse
import json
import logging
import signal
import sys
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Optional

from .models import ProxyConfig
from .process_manager import ProcessManager
from .session_manager import SessionManager
from .router import RequestRouter
from . import __version__

logger = logging.getLogger(__name__)


class ProxyHttpHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the proxy MCP server."""
    
    router: RequestRouter = None  # Set by server
    
    def log_message(self, format, *args):
        """Override to use logging module."""
        logger.debug("%s - %s", self.address_string(), format % args)
    
    def do_POST(self):
        """Handle POST requests."""
        if self.path == "/mcp":
            self._handle_mcp()
        else:
            self.send_error(404, "Not Found")
    
    def do_GET(self):
        """Handle GET requests (for SSE)."""
        if self.path == "/sse":
            self._handle_sse()
        else:
            self.send_error(404, "Not Found")
    
    def _handle_mcp(self):
        """Handle MCP JSON-RPC requests."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            request = json.loads(body.decode("utf-8"))
            
            response = self.router.route(request)
            
            if response is None:
                # Notification, no response needed
                self.send_response(204)
                self.end_headers()
                return
            
            response_body = json.dumps(response).encode("utf-8")
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(response_body))
            self.end_headers()
            self.wfile.write(response_body)
            
        except json.JSONDecodeError as e:
            self._send_json_error(-32700, f"Parse error: {e}")
        except Exception as e:
            logger.exception(f"Error handling MCP request: {e}")
            self._send_json_error(-32603, f"Internal error: {e}")
    
    def _handle_sse(self):
        """Handle SSE connections."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        
        # Send initial connection event
        self.wfile.write(b"event: connected\ndata: {}\n\n")
        self.wfile.flush()
        
        # Keep connection open
        try:
            while True:
                # Send keepalive
                self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
                import time
                time.sleep(30)
        except (BrokenPipeError, ConnectionResetError):
            pass
    
    def _send_json_error(self, code: int, message: str):
        """Send a JSON-RPC error response."""
        response = {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": code, "message": message},
        }
        response_body = json.dumps(response).encode("utf-8")
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response_body))
        self.end_headers()
        self.wfile.write(response_body)


class ProxyMcpServer:
    """Main proxy MCP server."""
    
    def __init__(self, config: ProxyConfig):
        """Initialize the server.
        
        Args:
            config: Server configuration
        """
        self.config = config
        config.validate()
        
        self.process_manager = ProcessManager(
            host=config.host,
            request_timeout=config.request_timeout,
        )
        self.session_manager = SessionManager(
            max_processes=config.max_processes,
            process_manager=self.process_manager,
        )
        self.router = RequestRouter(self.session_manager)
        self._server: Optional[ThreadingHTTPServer] = None
    
    def serve(self):
        """Start the HTTP server."""
        # Ensure default idalib-mcp process is running
        try:
            logger.info("Ensuring default idalib-mcp process is available...")
            default_info = self.process_manager.ensure_default_process()
            logger.info(f"Default idalib-mcp process ready on port {default_info.port}")
            
            # Fetch tools from the default process
            self.router.refresh_tools()
        except Exception as e:
            logger.error(f"Failed to start default idalib-mcp process: {e}")
            logger.warning("Server will start but tools/list will be empty until a binary is opened")
        
        # Set router on handler class
        ProxyHttpHandler.router = self.router
        
        self._server = ThreadingHTTPServer(
            (self.config.host, self.config.port),
            ProxyHttpHandler,
        )
        
        logger.info(
            f"IDA Pro Proxy MCP server v{__version__} starting on "
            f"http://{self.config.host}:{self.config.port}"
        )
        logger.info(f"Max processes: {self.config.max_processes}")
        
        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Shutdown the server and all child processes."""
        if hasattr(self, '_shutdown_called') and self._shutdown_called:
            return  # Already shutting down
        self._shutdown_called = True
        
        logger.info("Shutting down...")
        
        # First stop all child processes
        try:
            self.session_manager.close_all()
        except Exception as e:
            logger.warning(f"Error closing sessions: {e}")
        
        try:
            self.process_manager.stop_all()
        except Exception as e:
            logger.warning(f"Error stopping processes: {e}")
        
        # Then shutdown HTTP server
        if self._server:
            try:
                self._server.shutdown()
            except Exception as e:
                logger.warning(f"Error shutting down HTTP server: {e}")
        
        logger.info("Shutdown complete")


def load_config(config_path: Optional[str] = None) -> ProxyConfig:
    """Load configuration from file.
    
    Args:
        config_path: Path to config file (optional)
        
    Returns:
        ProxyConfig instance
    """
    config = ProxyConfig()
    
    if config_path:
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                if "max_processes" in data:
                    config.max_processes = data["max_processes"]
                if "host" in data:
                    config.host = data["host"]
                if "port" in data:
                    config.port = data["port"]
                if "base_port" in data:
                    config.base_port = data["base_port"]
                if "request_timeout" in data:
                    config.request_timeout = data["request_timeout"]
        except FileNotFoundError:
            logger.warning(f"Config file not found: {config_path}")
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid config file: {e}")
    
    return config


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="IDA Pro Proxy MCP - Multi-binary analysis proxy"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to listen on (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8744,
        help="Port to listen on (default: 8744)",
    )
    parser.add_argument(
        "--max-processes",
        type=int,
        default=None,
        help="Maximum number of concurrent idalib-mcp processes (default: 2)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to configuration file",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    
    # Load config
    config = load_config(args.config)
    
    # Override with command line arguments
    config.host = args.host
    config.port = args.port
    if args.max_processes is not None:
        config.max_processes = args.max_processes
    
    # Create and run server
    server = ProxyMcpServer(config)
    
    # Flag to track shutdown state
    shutdown_event = threading.Event()
    
    # Setup signal handlers
    def signal_handler(signum, frame):
        if shutdown_event.is_set():
            # Already shutting down, force exit on second signal
            logger.warning("Forced exit on second signal")
            sys.exit(1)
        
        logger.info("Received signal, shutting down...")
        shutdown_event.set()
        
        # Shutdown HTTP server from a separate thread to avoid blocking
        # HTTPServer.shutdown() must be called from a different thread than serve_forever()
        def do_shutdown():
            server.shutdown()
        
        shutdown_thread = threading.Thread(target=do_shutdown, daemon=True)
        shutdown_thread.start()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        server.serve()
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        # Ensure cleanup happens
        if not shutdown_event.is_set():
            server.shutdown()


if __name__ == "__main__":
    main()
