from __future__ import annotations
import argparse
import asyncio
from typing import List, Sequence

from .scanner import scan_cidrs, scan_ips
from .utils import COMMON_PORTS, parse_ports, write_csv, expand_cidrs


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="portscanner",
        description="Simple asyncio-based internal network port scanner (no external deps).",
    )
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--cidr", nargs="+", help="CIDR ranges (e.g., 192.168.0.0/24 192.168.10.0/24)")
    target.add_argument("--ips", nargs="+", help="List of IPs to scan directly")

    ports_group = ap.add_mutually_exclusive_group()
    ports_group.add_argument("--ports", help="Specify ports (e.g., 22,80,443 or 1-1024,10250)")
    ports_group.add_argument("--common", action="store_true", help="Use common port set")

    ap.add_argument("--timeout", type=float, default=0.5, help="Port connection timeout (seconds)")
    ap.add_argument("--host-conc", type=int, default=256, help="Concurrent hosts to scan")
    ap.add_argument("--port-conc", type=int, default=128, help="Concurrent ports per host")
    ap.add_argument("--out", default=None, help="CSV output path (e.g., open_ports.csv). If not specified, no file is saved")
    ap.add_argument("--no-progress", action="store_true", help="Hide progress logs on stdout")
    return ap


def _resolve_ports(args) -> List[int]:
    if args.ports:
        return parse_ports(args.ports)
    if args.common or not args.ports:
        return list(COMMON_PORTS)
    # This branch is rarely reached, but is a safety net
    return list(COMMON_PORTS)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    ports = _resolve_ports(args)
    progress = not args.no_progress

    if args.ips:
        coro = scan_ips(
            ips=args.ips,
            ports=ports,
            timeout=args.timeout,
            host_concurrency=args.host_conc,
            port_concurrency=args.port_conc,
            progress=progress,
        )
    else:
        coro = scan_cidrs(
            cidrs=args.cidr,
            ports=ports,
            timeout=args.timeout,
            host_concurrency=args.host_conc,
            port_concurrency=args.port_conc,
            progress=progress,
        )

    results = asyncio.run(coro)

    if args.out:
        write_csv(results, args.out)
        if progress:
            print(f"[+] Results saved: {args.out}")

    # Print summary to stdout
    if not progress:
        # If progress logs were hidden, print only the summary
        total_hosts = len(results)
        total_pairs = sum(len(r.open_ports) for r in results)
        print(f"Open hosts: {total_hosts}, Open ip:port pairs: {total_pairs}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
