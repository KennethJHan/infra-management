"""
Public API for the portscanner package
"""
from .scanner import ScanResult, scan_cidrs, scan_ips
from .utils import COMMON_PORTS, parse_ports

__all__ = [
    "ScanResult",
    "scan_cidrs",
    "scan_ips",
    "COMMON_PORTS",
    "parse_ports",
]
