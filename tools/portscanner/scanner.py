from __future__ import annotations
import asyncio
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Set, Tuple


@dataclass(slots=True)
class ScanResult:
    ip: str
    open_ports: List[int]


async def _check_port(ip: str, port: int, timeout: float) -> bool:
    """
    Simple TCP connect scan. If connection is successful, consider the port open.
    """
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        if hasattr(writer, "wait_closed"):
            await writer.wait_closed()
        return True
    except Exception:
        return False


async def _scan_host(
    ip: str,
    ports: Sequence[int],
    port_sem: asyncio.Semaphore,
    timeout: float,
) -> ScanResult:
    open_ports: List[int] = []

    async def _probe(p: int) -> None:
        async with port_sem:
            if await _check_port(ip, p, timeout):
                open_ports.append(p)

    await asyncio.gather(*[_probe(p) for p in ports])
    open_ports.sort()
    return ScanResult(ip=ip, open_ports=open_ports)


async def scan_ips(
    ips: Sequence[str],
    ports: Sequence[int],
    timeout: float = 0.5,
    host_concurrency: int = 256,
    port_concurrency: int = 128,
    progress: bool = True,
) -> List[ScanResult]:
    """
    Perform asynchronous port scan for the given list of IPs and return the results.
    """
    host_sem = asyncio.Semaphore(host_concurrency)
    port_sem = asyncio.Semaphore(port_concurrency)
    results: List[ScanResult] = []

    async def _scan_one(ip: str) -> None:
        async with host_sem:
            res = await _scan_host(ip, ports, port_sem, timeout)
            if res.open_ports:
                if progress:
                    print(f"{res.ip}: {res.open_ports}")
                results.append(res)

    await asyncio.gather(*[asyncio.create_task(_scan_one(ip)) for ip in ips])
    # Sort results by IP in ascending (lexicographical) order
    results.sort(key=lambda r: r.ip)
    return results


async def scan_cidrs(
    cidrs: Sequence[str],
    ports: Sequence[int],
    timeout: float = 0.5,
    host_concurrency: int = 256,
    port_concurrency: int = 128,
    progress: bool = True,
) -> List[ScanResult]:
    """
    Scan the given CIDR ranges directly.
    Internally, expands the CIDRs to host IPs and calls scan_ips.
    """
    from .utils import expand_cidrs  # Delayed import (to avoid circular import)
    ips = expand_cidrs(cidrs)
    return await scan_ips(
        ips=ips,
        ports=ports,
        timeout=timeout,
        host_concurrency=host_concurrency,
        port_concurrency=port_concurrency,
        progress=progress,
    )
