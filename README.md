# infra-management

Infrastructure management tools for network scanning and monitoring operations.

## Features

- **Port Scanner**: Asynchronous TCP port scanner for internal networks
- **No external dependencies**: Uses only Python standard library
- **CSV reporting**: Export scan results for analysis
- **High performance**: Concurrent scanning with configurable limits

## Installation & Development Setup

### Prerequisites
- Python 3.8+

### Development Installation
```bash
# Clone the repository
git clone <repository-url>
cd infra-management

# Install in development mode (required for imports to work)
pip install -e .

# For testing and development tools
pip install -e ".[test]"
```

### Running Tests
```bash
pytest .
```

## Quick Start

### Basic Usage
```bash
# Scan a network range with common ports
python -m tools.portscanner.cli --cidr 192.168.1.0/24 --common --out results.csv

# Scan specific IPs
python -m tools.portscanner.cli --ips 192.168.1.1 192.168.1.10 --ports 22,80,443
```

### Programmatic Usage
```python
import asyncio
from tools.portscanner import scan_cidrs, COMMON_PORTS

results = asyncio.run(scan_cidrs(["192.168.1.0/24"], COMMON_PORTS))
for result in results:
    print(f"{result.ip}: {result.open_ports}")
```

> 📖 **For detailed usage, performance tuning, and operational guidelines, see [Port Scanner User Guide](./docs/portscanner.md)**

## Project Structure

```
infra-management/
├── tools/portscanner/     # Main port scanner package
│   ├── cli.py            # Command-line interface
│   ├── scanner.py        # Core scanning logic
│   └── utils.py          # Utility functions
├── tests/                # Test suite
├── scripts/              # Helper scripts
├── docs/                 # Documentation
└── pyproject.toml        # Project configuration
```

## Documentation

- [Port Scanner User Guide](./docs/portscanner.md) — Detailed usage guide, performance tuning, and safety guidelines

## Common Principles

- Operational tools are designed to be **read-only or audit-focused by default**.
- **Change management and prior notification** must be followed before execution.
- Results (CSV/logs) should be **stored in a central repository** (e.g., S3/NAS/Log system).
