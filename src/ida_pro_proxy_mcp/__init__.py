"""IDA Pro Proxy MCP - Multi-binary analysis proxy for ida-pro-mcp

This package provides a proxy MCP server that manages multiple idalib-mcp
processes, enabling simultaneous analysis of multiple binary files.
"""

__version__ = "0.1.1"

from .models import ProxySession, ProcessInfo, ProxyConfig
from .process_manager import ProcessManager
from .session_manager import SessionManager
from .router import RequestRouter
from .server import ProxyMcpServer

__all__ = [
    "ProxySession",
    "ProcessInfo",
    "ProxyConfig",
    "ProcessManager",
    "SessionManager",
    "RequestRouter",
    "ProxyMcpServer",
]
