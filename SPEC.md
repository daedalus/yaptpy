# SPEC.md — yaptpy

## Purpose
YAPT (Yet Another Payload Tool) is a CLI tool that generates highly obfuscated x86_64 reverse shell shellcode with multiple evasion techniques including encryption, encoding, polymorphic junk insertion, and anti-debug/anti-emulation features.

## Scope
- Generates x86_64 reverse shell shellcode for Linux
- Supports TCP IPv4 connections to attacker-controlled endpoints
- Provides multiple obfuscation techniques (XOR, rolling XOR, RLE, junk code)
- Supports anti-debug (ptrace) and anti-emulation (rdtsc/cpuid) techniques
- CLI interface with argparse

## Public API / Interface

### CLI Commands
- `yapt --ip <IP> --port <PORT>` - Generate basic reverse shell shellcode
- `yapt --ip <IP> --port <PORT> --junk` - Insert polymorphic junk code
- `yapt --ip <IP> --port <PORT> --obfuscate-path` - XOR obfuscate executable path
- `yapt --ip <IP> --port <PORT> --anti-debug` - Add ptrace anti-debugging check
- `yapt --ip <IP> --port <PORT> --anti-emulation` - Add rdtsc/cpuid anti-emulation
- `yapt --ip <IP> --port <PORT> --rle` - Apply RLE encoding with decoder stub
- `yapt --ip <IP> --port <PORT> --xor-key <KEY>` - Apply simple XOR encryption
- `yapt --ip <IP> --port <PORT> --rolling-xor-key <KEY>` - Apply rolling XOR encryption
- `yapt --ip <IP> --port <PORT> --indirect-syscalls` - Use indirect syscall gadget
- `yapt --ip <IP> --port <PORT> --stack-pivot` - Enable stack pivot
- `yapt -e <PATH>` - Specify executable path (default: /bin/sh)

### Public Functions

#### `generate_payload(ip, port, executable_path, junk, anti_emulation, stack_pivot, obfuscate_path, anti_debug, indirect_syscalls) -> bytes`
- Generates core reverse shell payload with optional features
- Args:
  - `ip: str` - Attacker IP address
  - `port: int` - Attacker listener port (1-65535)
  - `executable_path: str` - Path to executable for execve
  - `junk: bool` - Insert polymorphic junk code
  - `anti_emulation: bool` - Add anti-emulation techniques
  - `stack_pivot: bool` - Enable stack pivot
  - `obfuscate_path: bool` - XOR obfuscate executable path in memory
  - `anti_debug: bool` - Add ptrace anti-debugging check
  - `indirect_syscalls: bool` - Use indirect syscall gadget
- Returns: Raw shellcode bytes
- Raises: ValueError for invalid IP/port

#### `xor_encrypt(data: bytes, key: int) -> bytes`
- Encrypts data using simple byte-wise XOR
- Args:
  - `data: bytes` - Data to encrypt
  - `key: int` - XOR key (0-255)
- Returns: Encrypted bytes
- Raises: ValueError if key outside 0-255

#### `rolling_xor_encrypt(data: bytes, key: int) -> bytes`
- Encrypts data using rolling XOR (key increments)
- Args:
  - `data: bytes` - Data to encrypt
  - `key: int` - Starting XOR key (0-255)
- Returns: Encrypted bytes
- Raises: ValueError if key outside 0-255

#### `rle_encode(data: bytes) -> bytes`
- Encodes data using Run-Length Encoding
- Args:
  - `data: bytes` - Data to encode
- Returns: RLE encoded bytes

#### `generate_polymorphic_junk() -> bytes`
- Generates random non-functional assembly instructions
- Returns: Random junk assembly bytes

#### `remove_comments_from_assembly(assembly_code: str) -> str`
- Removes comments from assembly code
- Args:
  - `assembly_code: str` - Assembly code with comments
- Returns: Cleaned assembly code

#### `rle_decoder_stub(original_size: int) -> bytes`
- Generates RLE decoder stub
- Args:
  - `original_size: int` - Size of original payload
- Returns: Decoder stub bytes

#### `rolling_xor_decoder_stub(original_size: int, start_key: int) -> bytes`
- Generates rolling XOR decoder stub
- Args:
  - `original_size: int` - Size of encrypted payload
  - `start_key: int` - Starting XOR key
- Returns: Decoder stub bytes

## Data Formats
- Input: CLI arguments (IP, port, various boolean flags)
- Output: Raw shellcode bytes printed as `\xNN\xNN...` format
- Shellcode format: x86_64 Linux syscall-based reverse shell

## Edge Cases
1. Invalid IP address format - raises ValueError
2. Port outside 1-65535 range - raises ValueError
3. XOR key outside 0-255 - raises ValueError
4. Both --xor-key and --rolling-xor-key specified - CLI error
5. Port without IP - CLI error
6. Non-UTF8 characters in executable path - raises ValueError
7. RLE stub size calculation instability - raises RecursionError
8. Empty or minimal payload generation
9. Large payload sizes with RLE encoding
10. Assembly errors during payload generation

## Performance & Constraints
- Target: x86_64 Linux only
- Python: 3.11+
- Dependencies: pwntools only
- No network I/O (local payload generation only)
- Memory usage proportional to payload size
