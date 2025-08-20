#!/usr/bin/env python3
"""
Thin wrapper so ops can run:  python3 scripts/scan.py --cidr ... --common
"""
from tools.portscanner.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
