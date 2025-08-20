# Port Scanner Operations Guide

Detailed usage guide for the port scanner tool in production environments.

> 💡 **New to this project?** Start with the [main README](../README.md) for installation and basic usage.

## Overview

A lightweight, asynchronous TCP port scanner designed for internal network audits:
- **Zero external dependencies** - Uses only Python standard library
- **High performance** - Concurrent scanning with configurable limits  
- **CSV reporting** - Machine-readable output for analysis
- **Safety focused** - Built for internal/audit use with proper controls

**Key Details:**
- Package: `tools/portscanner/`
- Entry point: `python -m tools.portscanner.cli`
- Output format: CSV (`ip,port`)
- Target networks: Internal ranges (192.168.x.x, 10.x.x.x, etc.)

## 1. Command Line Examples
General scan (recommended port set)
```bash
python -m tools.portscanner.cli \
  --cidr 192.168.0.0/24 192.168.10.0/24 \
  --common \
  --timeout 0.4 \
  --out result.csv
```

Specific port range (e.g., 1–1024)
```bash
python -m tools.portscanner.cli --cidr 192.168.0.0/24 --ports 1-1024 --timeout 0.3 --out result.csv
```

Scan specific IPs only (e.g., check SSH, RDP)
```bash
python -m tools.portscanner.cli --ips 192.168.0.10 192.168.0.20 --ports 22,3389
```

Hide progress logs (show summary only)
```bash
python -m tools.portscanner.cli --cidr 192.168.0.0/24 --common --no-progress
```