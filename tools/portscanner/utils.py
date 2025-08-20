from __future__ import annotations
import csv
import ipaddress
from typing import Iterable, List, Sequence


# Commonly used port set (modify as needed)
COMMON_PORTS: List[int] = sorted({
    # Infra/Management
    22, 23, 3389, 5900, 8530, 8531,
    # Web
    80, 443, 8080, 8443, 8000, 8888,
    # DB/Middleware
    1433, 1521, 3306, 5432, 6379, 11211, 27017, 9200, 9300,
    # Mail/Directory/File sharing, etc.
    25, 110, 143, 389, 636, 445, 139, 21,
})


def parse_ports(ports_arg: str) -> List[int]:
    """
    Parses strings like "22,80,443" or "1-1024,3306,5432" and returns a sorted, deduplicated list of ports.
    """
    ports: List[int] = []
    for token in ports_arg.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            a, b = token.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(token))
    return sorted(set(p for p in ports if 1 <= int(p) <= 65535))


def expand_cidrs(cidrs: Sequence[str]) -> List[str]:
    """
    Takes a list of CIDRs and expands them into a list of host IP strings (excluding network/broadcast addresses).
    """
    ips: List[str] = []
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        ips.extend(str(h) for h in net.hosts())
    return ips


def write_csv(results: Iterable["ScanResult"], out_path: str) -> None:
    """
    Saves scan results in CSV (ip, port) format.
    """
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "port"])
        for r in results:
            for p in sorted(r.open_ports):
                w.writerow([r.ip, p])
