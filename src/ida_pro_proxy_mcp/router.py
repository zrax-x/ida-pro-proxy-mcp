"""Request Router for IDA Pro Proxy MCP"""

import json
import logging
from typing import Any, Dict, Optional

from .session_manager import SessionManager

logger = logging.getLogger(__name__)


class RequestRouter:
    """Routes MCP requests to appropriate handlers or child processes.
    
    Session management tools (idalib_open, idalib_close, etc.) are handled
    directly by the proxy. Analysis tools are forwarded to the appropriate
    idalib-mcp process based on the session parameter.
    """
    
    # Tools that are handled by the proxy itself
    SESSION_TOOLS = {
        'idalib_open',
        'idalib_close', 
        'idalib_switch',
        'idalib_list',
        'idalib_current',
    }
    
    # Schema definitions for session tools
    SESSION_TOOL_SCHEMAS = {
        'idalib_open': {
            'name': 'idalib_open',
            'description': 'Open a binary file for analysis. Creates a new session.',
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'input_path': {
                        'type': 'string',
                        'description': 'Path to the binary file to analyze',
                    },
                    'run_auto_analysis': {
                        'type': 'boolean',
                        'description': 'Run IDA auto-analysis (default: true)',
                        'default': True,
                    },
                },
                'required': ['input_path'],
            },
            'outputSchema': {
                'type': 'object',
                'properties': {
                    'success': {'type': 'boolean'},
                    'session': {
                        'type': 'object',
                        'properties': {
                            'session_id': {'type': 'string'},
                            'binary_path': {'type': 'string'},
                            'binary_name': {'type': 'string'},
                            'process_port': {'type': 'integer'},
                        },
                    },
                    'message': {'type': 'string'},
                },
            },
        },
        'idalib_close': {
            'name': 'idalib_close',
            'description': 'Close a session and release its resources.',
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'session_id': {
                        'type': 'string',
                        'description': 'Session ID to close',
                    },
                },
                'required': ['session_id'],
            },
            'outputSchema': {
                'type': 'object',
                'properties': {
                    'success': {'type': 'boolean'},
                    'message': {'type': 'string'},
                    'error': {'type': 'string'},
                },
            },
        },
        'idalib_switch': {
            'name': 'idalib_switch',
            'description': 'Switch to a different session.',
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'session_id': {
                        'type': 'string',
                        'description': 'Session ID to switch to',
                    },
                },
                'required': ['session_id'],
            },
            'outputSchema': {
                'type': 'object',
                'properties': {
                    'success': {'type': 'boolean'},
                    'session': {'type': 'object'},
                    'message': {'type': 'string'},
                },
            },
        },
        'idalib_list': {
            'name': 'idalib_list',
            'description': 'List all open sessions.',
            'inputSchema': {
                'type': 'object',
                'properties': {},
            },
            'outputSchema': {
                'type': 'object',
                'properties': {
                    'sessions': {
                        'type': 'array',
                        'items': {'type': 'object'},
                    },
                    'count': {'type': 'integer'},
                    'current_session_id': {'type': ['string', 'null']},
                },
            },
        },
        'idalib_current': {
            'name': 'idalib_current',
            'description': 'Get the current active session.',
            'inputSchema': {
                'type': 'object',
                'properties': {},
            },
            'outputSchema': {
                'type': 'object',
                'properties': {
                    'session_id': {'type': 'string'},
                    'binary_path': {'type': 'string'},
                    'binary_name': {'type': 'string'},
                    'process_port': {'type': 'integer'},
                },
            },
        },
    }
    
    def __init__(self, session_manager: SessionManager):
        """Initialize the router.
        
        Args:
            session_manager: SessionManager instance
        """
        self.session_manager = session_manager
        self._cached_tools = []  # Cached tools from child process
    
    def refresh_tools(self) -> None:
        """Refresh the cached tools list from the default process.
        
        This should be called after the default process is started.
        """
        default_port = self.session_manager.process_manager.get_default_port()
        if default_port is None:
            logger.warning("No default process available for tools refresh")
            return
        
        try:
            response = self.session_manager.process_manager.forward_request(
                default_port,
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
            )
            if "result" in response:
                self._cached_tools = response["result"].get("tools", [])
                logger.info(f"Cached {len(self._cached_tools)} tools from default process")
        except Exception as e:
            logger.warning(f"Failed to refresh tools: {e}")
    
    def route(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Route a JSON-RPC request to the appropriate handler.
        
        Args:
            request: JSON-RPC request dictionary
            
        Returns:
            JSON-RPC response dictionary
        """
        method = request.get("method", "")
        request_id = request.get("id")
        
        try:
            if method == "initialize":
                return self._handle_initialize(request)
            elif method == "tools/list":
                return self._handle_tools_list(request)
            elif method == "tools/call":
                return self._handle_tools_call(request)
            elif method.startswith("notifications/"):
                # Notifications don't need responses
                return None
            else:
                # Forward other methods to current session's process
                return self._forward_to_current(request)
        except Exception as e:
            logger.exception(f"Error routing request: {e}")
            return self._error_response(request_id, -32603, f"Internal error: {e}")
    
    def _handle_initialize(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP initialize request."""
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": "ida-pro-proxy-mcp",
                    "version": "0.1.0",
                },
            },
        }
    
    def _handle_tools_list(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tools/list request.
        
        Returns the list of available tools, combining proxy tools with
        tools from a child process.
        """
        # Get tools from current session or use cached tools
        current = self.session_manager.get_current_session()
        child_tools = []
        
        if current:
            try:
                response = self.session_manager.process_manager.forward_request(
                    current.process_port,
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
                )
                if "result" in response:
                    child_tools = response["result"].get("tools", [])
            except Exception as e:
                logger.warning(f"Failed to get tools from child process: {e}")
                # Fall back to cached tools
                child_tools = self._cached_tools
        else:
            # No current session, try default process or use cached tools
            default_port = self.session_manager.process_manager.get_default_port()
            if default_port:
                try:
                    response = self.session_manager.process_manager.forward_request(
                        default_port,
                        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
                    )
                    if "result" in response:
                        child_tools = response["result"].get("tools", [])
                except Exception as e:
                    logger.warning(f"Failed to get tools from default process: {e}")
                    child_tools = self._cached_tools
            else:
                child_tools = self._cached_tools
        
        # Add session parameter to non-session tools and filter out duplicates
        modified_tools = []
        for tool in child_tools:
            tool_name = tool.get("name", "")
            # Skip tools that are already handled by the proxy (avoid duplicates)
            if tool_name in self.SESSION_TOOLS:
                continue
            # Add session parameter to analysis tools
            schema = tool.get("inputSchema", {})
            properties = schema.get("properties", {})
            properties["session"] = {
                "type": "string",
                "description": "Session ID to use (optional, uses current session if not specified)",
            }
            schema["properties"] = properties
            tool["inputSchema"] = schema
            modified_tools.append(tool)
        
        # Add session tools at the beginning of the list
        session_tools = [self.SESSION_TOOL_SCHEMAS[name] for name in self.SESSION_TOOLS]
        all_tools = session_tools + modified_tools
        
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {"tools": all_tools},
        }
    
    def _handle_tools_call(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tools/call request."""
        params = request.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        request_id = request.get("id")
        
        if tool_name in self.SESSION_TOOLS:
            return self._handle_session_tool(request_id, tool_name, arguments)
        else:
            return self._handle_analysis_tool(request_id, tool_name, arguments)
    
    def _handle_session_tool(
        self, request_id: Any, tool_name: str, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle session management tools."""
        try:
            if tool_name == "idalib_open":
                return self._handle_idalib_open(request_id, arguments)
            elif tool_name == "idalib_close":
                return self._handle_idalib_close(request_id, arguments)
            elif tool_name == "idalib_switch":
                return self._handle_idalib_switch(request_id, arguments)
            elif tool_name == "idalib_list":
                return self._handle_idalib_list(request_id)
            elif tool_name == "idalib_current":
                return self._handle_idalib_current(request_id)
            else:
                return self._error_response(request_id, -32601, f"Unknown tool: {tool_name}")
        except Exception as e:
            logger.exception(f"Error handling session tool {tool_name}: {e}")
            return self._tool_error_response(request_id, str(e))
    
    def _handle_idalib_open(self, request_id: Any, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle idalib_open tool call."""
        input_path = arguments.get("input_path")
        if not input_path:
            return self._tool_error_response(request_id, "input_path is required")
        
        run_auto_analysis = arguments.get("run_auto_analysis", True)
        
        try:
            session = self.session_manager.open_session(input_path, run_auto_analysis)
            result = {
                "success": True,
                "session": session.to_dict(),
                "message": f"Binary opened successfully: {session.binary_name}",
            }
            return self._tool_response(request_id, result)
        except FileNotFoundError as e:
            return self._tool_error_response(request_id, str(e))
        except RuntimeError as e:
            return self._tool_error_response(request_id, str(e))
    
    def _handle_idalib_close(self, request_id: Any, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle idalib_close tool call."""
        session_id = arguments.get("session_id")
        if not session_id:
            return self._tool_error_response(request_id, "session_id is required")
        
        if self.session_manager.close_session(session_id):
            result = {"success": True, "message": f"Session closed: {session_id}"}
        else:
            result = {"success": False, "error": f"Session not found: {session_id}"}
        
        return self._tool_response(request_id, result)
    
    def _handle_idalib_switch(self, request_id: Any, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle idalib_switch tool call."""
        session_id = arguments.get("session_id")
        if not session_id:
            return self._tool_error_response(request_id, "session_id is required")
        
        try:
            session = self.session_manager.switch_session(session_id)
            result = {
                "success": True,
                "session": session.to_dict(),
                "message": f"Switched to session: {session_id}",
            }
            return self._tool_response(request_id, result)
        except ValueError as e:
            return self._tool_error_response(request_id, str(e))
    
    def _handle_idalib_list(self, request_id: Any) -> Dict[str, Any]:
        """Handle idalib_list tool call."""
        sessions = self.session_manager.list_sessions()
        current = self.session_manager.get_current_session()
        
        result = {
            "sessions": sessions,
            "count": len(sessions),
            "current_session_id": current.session_id if current else None,
        }
        return self._tool_response(request_id, result)
    
    def _handle_idalib_current(self, request_id: Any) -> Dict[str, Any]:
        """Handle idalib_current tool call."""
        session = self.session_manager.get_current_session()
        
        if session is None:
            return self._tool_error_response(
                request_id, 
                "No active session. Use idalib_open() to open a binary first."
            )
        
        return self._tool_response(request_id, session.to_dict())
    
    def _handle_analysis_tool(
        self, request_id: Any, tool_name: str, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle analysis tools by forwarding to child process."""
        # Extract session parameter
        session_id = arguments.pop("session", None)
        
        # Get target session
        if session_id:
            session = self.session_manager.get_session(session_id)
            if session is None:
                return self._tool_error_response(
                    request_id,
                    f"Session not found: {session_id}. Use idalib_open() to create a session first."
                )
        else:
            session = self.session_manager.get_current_session()
            if session is None:
                return self._tool_error_response(
                    request_id,
                    "No active session. Use idalib_open() to open a binary first."
                )
        
        # Update LRU
        session.touch()
        
        # Check if process is healthy
        if not self.session_manager.process_manager.check_process_health(session.process_port):
            # Process crashed, clean up
            self.session_manager.close_session(session.session_id)
            return self._tool_error_response(
                request_id,
                f"Session {session.session_id} is no longer available (process crashed)"
            )
        
        # Forward request to child process
        child_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }
        
        try:
            response = self.session_manager.process_manager.forward_request(
                session.process_port, child_request
            )
            # Return the child's response with our request ID
            response["id"] = request_id
            return response
        except RuntimeError as e:
            return self._tool_error_response(request_id, str(e))
    
    def _forward_to_current(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Forward a request to the current session's process."""
        session = self.session_manager.get_current_session()
        
        if session is None:
            return self._error_response(
                request.get("id"),
                -32001,
                "No active session. Use idalib_open() to open a binary first."
            )
        
        try:
            return self.session_manager.process_manager.forward_request(
                session.process_port, request
            )
        except RuntimeError as e:
            return self._error_response(request.get("id"), -32000, str(e))
    
    def _tool_response(self, request_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
        """Create a successful tool response.
        
        Includes both content (for display) and structuredContent (for schema validation).
        """
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [
                    {"type": "text", "text": json.dumps(result, indent=2)}
                ],
                "structuredContent": result,
                "isError": False,
            },
        }
    
    def _tool_error_response(self, request_id: Any, error: str) -> Dict[str, Any]:
        """Create a tool error response.
        
        Includes both content (for display) and structuredContent (for schema validation).
        """
        error_result = {"error": error}
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [
                    {"type": "text", "text": json.dumps(error_result)}
                ],
                "structuredContent": error_result,
                "isError": True,
            },
        }
    
    def _error_response(self, request_id: Any, code: int, message: str) -> Dict[str, Any]:
        """Create a JSON-RPC error response."""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }
