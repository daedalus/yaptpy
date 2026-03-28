# SPEC.md — yaptpy

## Purpose
YAPT (Yet Another Payload Tool) is a CLI tool that generates highly obfuscated reverse shell shellcode for Linux with multiple evasion techniques including encryption, encoding, polymorphic junk insertion, and anti-debug/anti-emulation features.

## Scope
- Generates x86_64 and ARM64 reverse shell shellcode for Linux
- Supports TCP IPv4/IPv6 connections to attacker-controlled endpoints
- Supports bind shells and DNS resolution payloads
- Provides multiple obfuscation techniques (XOR, rolling XOR, RLE, Base64, Base32, AES, RC4)
- Supports anti-debug (ptrace), anti-emulation (rdtsc/cpuid), VM detection, and parent process checks
- Provides egg hunter, staged payloads, and advanced polymorphic obfuscation
- CLI interface with argparse

## Supported Architectures
- x86_64 (amd64) - Default
- ARM64 (aarch64) - With reverse shell and bind shell support

## Payload Types

### Reverse Shell (default)
- Standard reverse TCP shell connecting back to attacker
- Supports IPv4 and IPv6

### Bind Shell
- Listener on specified port instead of reverse connect
- Configurable bind address (default: 0.0.0.0)

### DNS Resolution
- Performs DNS resolution for domain-based C2
- Can be used with domain fronting

### Egg Hunter
- Small stub that searches memory for egg marker
- Used for staged payloads where main shellcode is injected later

### Staged Payload (Dropper)
- Small initial stage that downloads/fetches larger payload
- Stage 1: Download stub
- Stage 2: Downloaded payload (typically shell)

## Evasion Techniques

### Encryption
1. **XOR (Simple)** - Byte-wise XOR with single key
2. **Rolling XOR** - Key increments for each byte
3. **AES-256-CBC** - Block cipher encryption with IV
4. **RC4** - Stream cipher encryption

### Encoding
1. **Base64** - Standard Base64 encoding
2. **Base32** - Standard Base32 encoding
3. **RLE (Run-Length Encoding)** - Compression with self-decoding stub
4. **LZ77** - LZ77 compression with self-decompressing stub

### Obfuscation
1. **Polymorphic Junk** - Random non-functional assembly instructions
2. **Enhanced Polymorphic Engine** - Advanced mutation with configurable junk ratio
3. **Path Obfuscation** - XOR obfuscation of executable path in memory
4. **Indirect Syscalls** - Call to syscall gadget instead of direct syscall
5. **Stack Pivot** - Adjust stack pointer to evade detection
6. **Instruction Substitution** - Replace instructions with equivalent variants
7. **Code Transposition** - Reorder non-dependent instructions
8. **Call Preceded (Call4)** - Hide syscall with call instructions
9. **Syscall Splitting** - Interleave syscall with other instructions

### Anti-Analysis
1. **Anti-Debug (ptrace)** - Check if process is being traced
2. **Anti-Emulation (rdtsc/cpuid)** - Timing checks to detect emulators
3. **VM/Hypervisor Detection** - Check for VMware, Hyper-V, QEMU artifacts
4. **Parent Process Check** - Exit if parent is suspicious (sandbox/debugger)
5. **Sleep Evasion** - Timing delays to bypass sandbox timeout

## Public API / Interface

### CLI Commands

#### Connection Arguments
- `--ip <IP>` - Attacker IP address (for reverse shell)
- `--port <PORT>` - Attacker listener port
- `--domain <DOMAIN>` - Domain name for DNS resolution
- `--bind-addr <ADDR>` - Bind address for bind shell (default: 0.0.0.0)
- `-e, --executable <PATH>` - Executable path for execve (default: /bin/sh)

#### Payload Type Arguments
- `--reverse` - Reverse shell (default)
- `--bind` - Bind shell instead of reverse
- `--dns` - DNS resolution payload
- `--ipv6` - Use IPv6 for connection

#### Obfuscation & Evasion Arguments
- `--xor-key <KEY>` - Simple XOR encryption key (0-255)
- `--rolling-xor-key <KEY>` - Rolling XOR encryption key (0-255)
- `--rle` - Enable RLE encoding with self-decoder stub
- `--lz77` - Enable LZ77 compression with self-decompressor stub
- `--base64` - Apply Base64 encoding
- `--base32` - Apply Base32 encoding
- `--aes-key <KEY>` - AES encryption key (hex, 16/24/32 bytes)
- `--rc4-key <KEY>` - RC4 encryption key (hex)
- `--junk` - Insert polymorphic junk code
- `--obfuscate-path` - XOR obfuscate executable path in memory
- `--indirect-syscalls` - Use indirect syscall gadget
- `--anti-emulation` - Add rdtsc/cpuid anti-emulation
- `--anti-debug` - Add ptrace anti-debugging check
- `--stack-pivot` - Enable stack pivot (sub rsp, 0x500)

#### Advanced Evasion Arguments
- `--sleep <SECONDS>` - Sleep before execution (sandbox bypass)
- `--vm-detect` - Enable VM/hypervisor detection
- `--parent-check` - Check parent process for suspicious activity
- `--egg <HEX>` - Egg marker for egg hunter (4 bytes)
- `--egg-hunter` - Generate egg hunter instead of full payload
- `--staged` - Generate staged payload (dropper)
- `--polymorphic` - Apply enhanced polymorphic obfuscation

### Public Functions

#### Payload Generation
- `generate_payload(...) -> bytes` - Generate shellcode with all options
- `egg_hunter(egg: bytes) -> bytes` - Generate egg hunter
- `generate_bind_shell(port: int, bind_addr: str) -> bytes` - Generate bind shell
- `generate_ipv6_reverse_shell(ipv6_addr: str, port: int) -> bytes` - Generate IPv6 reverse shell
- `generate_dns_resolve(domain: str) -> bytes` - Generate DNS resolver
- `generate_staged_payload(stage1_size: int) -> tuple[bytes, bytes]` - Generate staged payload

#### Encryption
- `xor_encrypt(data: bytes, key: int) -> bytes` - Simple XOR
- `rolling_xor_encrypt(data: bytes, key: int) -> bytes` - Rolling XOR
- `base64_encode(data: bytes) -> bytes` - Base64 encoding
- `base32_encode(data: bytes) -> bytes` - Base32 encoding
- `aes_encrypt(data: bytes, key: bytes) -> bytes` - AES-CBC encryption
- `rc4_encrypt(data: bytes, key: bytes) -> bytes` - RC4 encryption

#### Evasion
- `generate_sleep_evasion(sleep_seconds: int) -> bytes` - Sleep evasion code
- `generate_vm_detection() -> bytes` - VM detection code
- `generate_parent_check() -> bytes` - Parent process check code

#### Obfuscation
- `substitute_instructions(asm_code: str) -> str` - Instruction substitution
- `transposed_code(asm_lines: list[str]) -> list[str]` - Code transposition
- `call_preceded_obfuscation(syscall_num: int) -> bytes` - Call preceded obfuscation
- `syscall_splitting(syscall_num: int) -> bytes` - Syscall splitting
- `enhanced_polymorphic_engine(shellcode: bytes, junk_ratio: float) -> bytes` - Enhanced polymorphic

#### Utility
- `api_hash(syscall_name: str) -> int` - Compute syscall hash
- `generate_polymorphic_junk() -> bytes` - Random junk assembly
- `remove_comments_from_assembly(assembly_code: str) -> str` - Remove comments
- `rle_decoder_stub(original_size: int) -> bytes` - RLE decoder stub
- `rolling_xor_decoder_stub(original_size: int, start_key: int) -> bytes` - Rolling XOR decoder

#### ARM64 Specific
- `generate_arm64_reverse_shell(ip: str, port: int, executable_path: str) -> bytes` - Generate ARM64 reverse shell
- `generate_arm64_bind_shell(port: int, bind_addr: str) -> bytes` - Generate ARM64 bind shell
- `generate_arm64_payload(...) -> bytes` - Generate ARM64 payload with specified type

## Data Formats
- Input: CLI arguments (IP, port, architecture, various boolean flags)
- Output: Raw shellcode bytes printed as `\xNN\xNN...` format
- Shellcode format: x86_64 or ARM64 Linux syscall-based reverse/bind shell

## Edge Cases
1. Invalid IP address format - raises ValueError
2. Invalid IPv6 address format - raises ValueError
3. Port outside 1-65535 range - raises ValueError
4. XOR key outside 0-255 - raises ValueError
5. Invalid AES key size (not 16/24/32 bytes) - raises ValueError
6. Both --xor-key and --rolling-xor-key specified - CLI error
7. Both --base64 and --base32 specified - CLI error
8. Port without IP (non-bind) - CLI error
9. Non-UTF8 characters in executable path - raises ValueError
10. RLE stub size calculation instability - raises RecursionError
11. Egg not exactly 4 bytes - raises ValueError
12. Empty or minimal payload generation
13. Large payload sizes with RLE encoding
14. Assembly errors during payload generation
15. Unsupported features for ARM64 (egg hunter, staged, polymorphic) - CLI error

## Performance & Constraints
- Target: x86_64 or ARM64 Linux only
- Python: 3.11+
- Dependencies: pwntools, cryptography
- No network I/O (local payload generation only)
- Memory usage proportional to payload size
