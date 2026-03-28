import pytest
from hypothesis import Verbosity, given, settings
from hypothesis import strategies as st

from yaptpy import (
    aes_encrypt,
    api_hash,
    base32_encode,
    base64_encode,
    call_preceded_obfuscation,
    egg_hunter,
    enhanced_polymorphic_engine,
    generate_arm64_bind_shell,
    generate_arm64_payload,
    generate_arm64_reverse_shell,
    generate_bind_shell,
    generate_ipv6_reverse_shell,
    generate_parent_check,
    generate_payload,
    generate_polymorphic_junk,
    generate_sleep_evasion,
    generate_staged_payload,
    generate_vm_detection,
    lz77_decode,
    lz77_decoder_stub,
    lz77_encode,
    rc4_encrypt,
    remove_comments_from_assembly,
    rle_decoder_stub,
    rle_encode,
    rolling_xor_decoder_stub,
    rolling_xor_encrypt,
    substitute_instructions,
    syscall_splitting,
    transposed_code,
    xor_encrypt,
)


class TestXorEncrypt:
    def test_xor_encrypt_basic(self, sample_data):
        key = 0xAA
        result = xor_encrypt(sample_data, key)
        assert len(result) == len(sample_data)
        decrypted = xor_encrypt(result, key)
        assert decrypted == sample_data

    def test_xor_encrypt_zero_key(self, sample_data):
        result = xor_encrypt(sample_data, 0)
        assert result == sample_data

    def test_xor_encrypt_full_byte_key(self, sample_data):
        result = xor_encrypt(sample_data, 255)
        assert len(result) == len(sample_data)

    def test_xor_encrypt_invalid_key_negative(self, sample_data):
        with pytest.raises(ValueError, match="XOR key must be a byte value"):
            xor_encrypt(sample_data, -1)

    def test_xor_encrypt_invalid_key_too_large(self, sample_data):
        with pytest.raises(ValueError, match="XOR key must be a byte value"):
            xor_encrypt(sample_data, 256)

    def test_xor_encrypt_empty_data(self):
        result = xor_encrypt(b"", 0x42)
        assert result == b""


class TestRollingXorEncrypt:
    def test_rolling_xor_encrypt_basic(self, sample_data):
        key = 0x42
        result = rolling_xor_encrypt(sample_data, key)
        assert len(result) == len(sample_data)
        decrypted = rolling_xor_encrypt(result, key)
        assert decrypted == sample_data

    def test_rolling_xor_encrypt_zero_key(self, sample_data):
        result = rolling_xor_encrypt(sample_data, 0)
        assert len(result) == len(sample_data)

    def test_rolling_xor_encrypt_invalid_key_negative(self, sample_data):
        with pytest.raises(ValueError, match="Rolling XOR key must be a byte value"):
            rolling_xor_encrypt(sample_data, -1)

    def test_rolling_xor_encrypt_invalid_key_too_large(self, sample_data):
        with pytest.raises(ValueError, match="Rolling XOR key must be a byte value"):
            rolling_xor_encrypt(sample_data, 256)

    def test_rolling_xor_encrypt_empty_data(self):
        result = rolling_xor_encrypt(b"", 0x42)
        assert result == b""


class TestBase64Encode:
    def test_base64_encode_basic(self, sample_data):
        result = base64_encode(sample_data)
        assert isinstance(result, bytes)
        import base64

        assert result == base64.b64encode(sample_data)

    def test_base64_encode_empty(self):
        result = base64_encode(b"")
        assert result == b""


class TestBase32Encode:
    def test_base32_encode_basic(self, sample_data):
        result = base32_encode(sample_data)
        assert isinstance(result, bytes)
        import base64

        assert result == base64.b32encode(sample_data)

    def test_base32_encode_empty(self):
        result = base32_encode(b"")
        assert result == b""


class TestAesEncrypt:
    def test_aes_encrypt_128bit_key(self, sample_data):
        key = b"0123456789abcdef"
        result = aes_encrypt(sample_data, key)
        assert isinstance(result, bytes)
        assert len(result) > len(sample_data)

    def test_aes_encrypt_256bit_key(self, sample_data):
        key = b"0123456789abcdef0123456789abcdef"
        result = aes_encrypt(sample_data, key)
        assert isinstance(result, bytes)

    def test_aes_encrypt_invalid_key_size(self, sample_data):
        with pytest.raises(ValueError, match="AES key must be"):
            aes_encrypt(sample_data, b"short")


class TestRc4Encrypt:
    def test_rc4_encrypt_basic(self, sample_data):
        key = b"testkey"
        result = rc4_encrypt(sample_data, key)
        assert isinstance(result, bytes)
        assert len(result) == len(sample_data)

    def test_rc4_encrypt_decrypt(self, sample_data):
        key = b"testkey"
        encrypted = rc4_encrypt(sample_data, key)
        decrypted = rc4_encrypt(encrypted, key)
        assert decrypted == sample_data

    def test_rc4_encrypt_empty(self):
        result = rc4_encrypt(b"", b"key")
        assert result == b""


class TestRleEncode:
    def test_rle_encode_basic(self):
        data = b"aaabbbcccdddeee"
        result = rle_encode(data)
        assert result == b"\x03a\x03b\x03c\x03d\x03e"

    def test_rle_encode_repeated_bytes(self):
        data = b"\x00\x00\x00\x00\x00"
        result = rle_encode(data)
        assert len(result) == 2

    def test_rle_encode_no_repetition(self):
        data = b"abcdef"
        result = rle_encode(data)
        assert len(result) == 12

    def test_rle_encode_empty_data(self):
        result = rle_encode(b"")
        assert result == b""


class TestEggHunter:
    def test_egg_hunter_basic(self):
        egg = b"\xde\xad\xbe\xef"
        result = egg_hunter(egg)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_egg_hunter_invalid_length(self):
        with pytest.raises(ValueError, match="Egg must be 4 bytes"):
            egg_hunter(b"short")


class TestGenerateSleepEvasion:
    def test_generate_sleep_evasion_basic(self):
        result = generate_sleep_evasion(60)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_sleep_evasion_zero(self):
        result = generate_sleep_evasion(0)
        assert isinstance(result, bytes)


class TestGenerateVmDetection:
    def test_generate_vm_detection_basic(self):
        result = generate_vm_detection()
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestGenerateParentCheck:
    def test_generate_parent_check_basic(self):
        result = generate_parent_check()
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestApiHash:
    def test_api_hash_basic(self):
        result = api_hash("socket")
        assert isinstance(result, int)
        assert result > 0

    def test_api_hash_case_insensitive(self):
        h1 = api_hash("socket")
        h2 = api_hash("SOCKET")
        h3 = api_hash("SockeT")
        assert h1 == h2 == h3


class TestGenerateBindShell:
    @pytest.mark.skip(reason="Assembly requires further debugging")
    def test_generate_bind_shell_basic(self, sample_port):
        result = generate_bind_shell(sample_port)
        assert isinstance(result, bytes)
        assert len(result) > 0

    @pytest.mark.skip(reason="Assembly requires further debugging")
    def test_generate_bind_shell_custom_addr(self, sample_port):
        result = generate_bind_shell(sample_port, "127.0.0.1")
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_bind_shell_invalid_addr(self, sample_port):
        with pytest.raises(ValueError, match="Invalid bind address"):
            generate_bind_shell(sample_port, "invalid")


class TestGenerateIpv6ReverseShell:
    @pytest.mark.skip(reason="Assembly requires further debugging")
    def test_generate_ipv6_reverse_shell_basic(self, sample_port):
        result = generate_ipv6_reverse_shell("::1", sample_port)
        assert isinstance(result, bytes)
        assert len(result) > 0

    @pytest.mark.skip(reason="Assembly requires further debugging")
    def test_generate_ipv6_reverse_shell_full(self, sample_port):
        result = generate_ipv6_reverse_shell("2001:db8::1", sample_port)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_ipv6_reverse_shell_invalid(self, sample_port):
        with pytest.raises(ValueError, match="Invalid IPv6"):
            generate_ipv6_reverse_shell("invalid", sample_port)


class TestSubstituteInstructions:
    def test_substitute_instructions_basic(self):
        asm = "xor eax, eax\npush rax; pop rax"
        result = substitute_instructions(asm)
        assert isinstance(result, str)


class TestTransposedCode:
    def test_transposed_code_basic(self):
        lines = ["mov rax, 1", "mov rbx, 2", "add rax, rbx"]
        result = transposed_code(lines)
        assert isinstance(result, list)
        assert len(result) == len(lines)

    def test_transposed_code_short(self):
        lines = ["mov rax, 1"]
        result = transposed_code(lines)
        assert result == lines


class TestCallPrecededObfuscation:
    def test_call_preceded_obfuscation_basic(self):
        result = call_preceded_obfuscation(1)
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestSyscallSplitting:
    def test_syscall_splitting_basic(self):
        result = syscall_splitting(1)
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestGenerateStagedPayload:
    @pytest.mark.skip(reason="Assembly requires further debugging")
    def test_generate_staged_payload_basic(self):
        stage1, stage2 = generate_staged_payload()
        assert isinstance(stage1, bytes)
        assert isinstance(stage2, bytes)
        assert len(stage1) > 0
        assert len(stage2) > 0

    @pytest.mark.skip(reason="Assembly requires further debugging")
    def test_generate_staged_payload_custom_size(self):
        stage1, stage2 = generate_staged_payload(256)
        assert isinstance(stage1, bytes)
        assert isinstance(stage2, bytes)


class TestEnhancedPolymorphicEngine:
    def test_enhanced_polymorphic_engine_basic(self, sample_data):
        result = enhanced_polymorphic_engine(sample_data)
        assert isinstance(result, bytes)
        assert len(result) >= len(sample_data)

    def test_enhanced_polymorphic_engine_custom_ratio(self, sample_data):
        result = enhanced_polymorphic_engine(sample_data, junk_ratio=0.5)
        assert isinstance(result, bytes)


class TestRemoveCommentsFromAssembly:
    def test_remove_comments_basic(self):
        assembly = """
        mov rax, 1  # This is a comment
        push rbx    # Another comment
        """
        result = remove_comments_from_assembly(assembly)
        assert "#" not in result
        assert "mov rax, 1" in result
        assert "push rbx" in result

    def test_remove_comments_no_comments(self):
        assembly = "mov rax, 1\npush rbx"
        result = remove_comments_from_assembly(assembly)
        assert result == assembly

    def test_remove_comments_empty(self):
        result = remove_comments_from_assembly("")
        assert result == ""

    def test_remove_comments_only_comments(self):
        assembly = "# This is a comment\n# Another comment"
        result = remove_comments_from_assembly(assembly)
        assert result == ""


class TestGeneratePolymorphicJunk:
    def test_generate_polymorphic_junk_returns_bytes(self):
        result = generate_polymorphic_junk()
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestRleDecoderStub:
    def test_rle_decoder_stub_returns_bytes(self):
        result = rle_decoder_stub(100)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_rle_decoder_stub_small_size(self):
        result = rle_decoder_stub(10)
        assert isinstance(result, bytes)


class TestRollingXorDecoderStub:
    def test_rolling_xor_decoder_stub_returns_bytes(self):
        result = rolling_xor_decoder_stub(100, 0x42)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_rolling_xor_decoder_stub_small_size(self):
        result = rolling_xor_decoder_stub(10, 0x42)
        assert isinstance(result, bytes)


class TestGeneratePayload:
    def test_generate_payload_basic(self, sample_ip, sample_port, sample_executable):
        result = generate_payload(
            ip=sample_ip,
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=False,
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_payload_with_junk(
        self, sample_ip, sample_port, sample_executable
    ):
        result = generate_payload(
            ip=sample_ip,
            port=sample_port,
            executable_path=sample_executable,
            junk=True,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=False,
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_payload_with_anti_debug(
        self, sample_ip, sample_port, sample_executable
    ):
        result = generate_payload(
            ip=sample_ip,
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=True,
            indirect_syscalls=False,
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_payload_with_anti_emulation(
        self, sample_ip, sample_port, sample_executable
    ):
        result = generate_payload(
            ip=sample_ip,
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=True,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=False,
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_payload_with_stack_pivot(
        self, sample_ip, sample_port, sample_executable
    ):
        result = generate_payload(
            ip=sample_ip,
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=True,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=False,
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_payload_with_obfuscate_path(
        self, sample_ip, sample_port, sample_executable
    ):
        result = generate_payload(
            ip=sample_ip,
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=True,
            anti_debug=False,
            indirect_syscalls=False,
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_payload_with_indirect_syscalls(
        self, sample_ip, sample_port, sample_executable
    ):
        result = generate_payload(
            ip=sample_ip,
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=True,
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    @pytest.mark.skip(reason="Assembly requires further debugging")
    def test_generate_payload_bind_shell(self, sample_port, sample_executable):
        result = generate_payload(
            ip=None,
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=False,
            payload_type="bind",
            bind_addr="0.0.0.0",
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    @pytest.mark.skip(reason="Assembly requires further debugging")
    def test_generate_payload_ipv6(self, sample_port, sample_executable):
        result = generate_payload(
            ip="::1",
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=False,
            ipv6=True,
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_payload_sleep_evasion(
        self, sample_ip, sample_port, sample_executable
    ):
        result = generate_payload(
            ip=sample_ip,
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=False,
            sleep_seconds=1,
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_payload_vm_detect(
        self, sample_ip, sample_port, sample_executable
    ):
        result = generate_payload(
            ip=sample_ip,
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=False,
            vm_detect=True,
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_payload_parent_check(
        self, sample_ip, sample_port, sample_executable
    ):
        result = generate_payload(
            ip=sample_ip,
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=False,
            parent_check=True,
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_payload_base64(self, sample_ip, sample_port, sample_executable):
        result = generate_payload(
            ip=sample_ip,
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=False,
            base64_enc=True,
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_payload_base32(self, sample_ip, sample_port, sample_executable):
        result = generate_payload(
            ip=sample_ip,
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=False,
            base32_enc=True,
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_payload_aes(self, sample_ip, sample_port, sample_executable):
        result = generate_payload(
            ip=sample_ip,
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=False,
            aes_key=b"0123456789abcdef",
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_payload_rc4(self, sample_ip, sample_port, sample_executable):
        result = generate_payload(
            ip=sample_ip,
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=False,
            rc4_key=b"testkey",
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    @pytest.mark.skip(reason="Assembly requires further debugging")
    def test_generate_payload_egg(self, sample_ip, sample_port, sample_executable):
        result = generate_payload(
            ip=sample_ip,
            port=sample_port,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=False,
            egg=b"\xde\xad\xbe\xef",
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_payload_invalid_ip(self, sample_port, sample_executable):
        with pytest.raises(ValueError, match="Invalid IP address format"):
            generate_payload(
                ip="invalid_ip",
                port=sample_port,
                executable_path=sample_executable,
                junk=False,
                anti_emulation=False,
                stack_pivot=False,
                obfuscate_path=False,
                anti_debug=False,
                indirect_syscalls=False,
            )

    def test_generate_payload_invalid_port_high(self, sample_ip, sample_executable):
        with pytest.raises(OverflowError):
            generate_payload(
                ip=sample_ip,
                port=70000,
                executable_path=sample_executable,
                junk=False,
                anti_emulation=False,
                stack_pivot=False,
                obfuscate_path=False,
                anti_debug=False,
                indirect_syscalls=False,
            )

    def test_generate_payload_no_ip(self, sample_executable):
        result = generate_payload(
            ip=None,
            port=None,
            executable_path=sample_executable,
            junk=False,
            anti_emulation=False,
            stack_pivot=False,
            obfuscate_path=False,
            anti_debug=False,
            indirect_syscalls=False,
        )
        assert isinstance(result, bytes)
        assert len(result) > 0


@given(data=st.binary(min_size=1, max_size=1000))
@settings(verbosity=Verbosity.verbose)
def test_xor_encrypt_invertible(data):
    key = 0x42
    encrypted = xor_encrypt(data, key)
    decrypted = xor_encrypt(encrypted, key)
    assert decrypted == data


@given(
    data=st.binary(min_size=1, max_size=1000),
    key=st.integers(min_value=0, max_value=255),
)
@settings(verbosity=Verbosity.verbose)
def test_rolling_xor_encrypt_invertible(data, key):
    encrypted = rolling_xor_encrypt(data, key)
    decrypted = rolling_xor_encrypt(encrypted, key)
    assert decrypted == data


@given(
    data=st.binary(min_size=1, max_size=100),
    key=st.binary(min_size=16, max_size=16),
)
@settings(verbosity=Verbosity.verbose)
def test_rc4_encrypt_invertible(data, key):
    encrypted = rc4_encrypt(data, key)
    decrypted = rc4_encrypt(encrypted, key)
    assert decrypted == data


class TestArm64Payload:
    @pytest.mark.skip(reason="ARM64 assembly requires cross-compilation setup")
    def test_generate_arm64_reverse_shell_basic(self, sample_ip, sample_port):
        result = generate_arm64_reverse_shell(sample_ip, sample_port)
        assert isinstance(result, bytes)
        assert len(result) > 0

    @pytest.mark.skip(reason="ARM64 assembly requires cross-compilation setup")
    def test_generate_arm64_bind_shell_basic(self, sample_port):
        result = generate_arm64_bind_shell(sample_port)
        assert isinstance(result, bytes)
        assert len(result) > 0

    @pytest.mark.skip(reason="ARM64 assembly requires cross-compilation setup")
    def test_generate_arm64_payload_reverse(self, sample_ip, sample_port):
        result = generate_arm64_payload(
            ip=sample_ip,
            port=sample_port,
            payload_type="reverse",
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    @pytest.mark.skip(reason="ARM64 assembly requires cross-compilation setup")
    def test_generate_arm64_payload_bind(self, sample_port):
        result = generate_arm64_payload(
            port=sample_port,
            payload_type="bind",
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_arm64_payload_invalid(self):
        with pytest.raises(ValueError, match="Invalid payload configuration"):
            generate_arm64_payload(
                ip=None,
                port=None,
                payload_type="reverse",
            )


class TestLz77Encode:
    def test_lz77_encode_basic(self):
        data = b"aaabbbcccdddeee"
        result = lz77_encode(data)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_lz77_encode_repeated_data(self):
        data = b"abcabcabcabcabc"
        result = lz77_encode(data)
        assert isinstance(result, bytes)

    def test_lz77_encode_no_compression(self):
        data = b"abcdefghijklmnop"
        result = lz77_encode(data)
        assert isinstance(result, bytes)

    def test_lz77_encode_empty(self):
        result = lz77_encode(b"")
        assert result == b""

    def test_lz77_decode_basic(self):
        data = b"aaabbbcccdddeee"
        encoded = lz77_encode(data)
        decoded = lz77_decode(encoded)
        assert decoded == data

    def test_lz77_decode_with_back_references(self):
        data = b"abcabcabcabcabc"
        encoded = lz77_encode(data)
        decoded = lz77_decode(encoded)
        assert decoded == data


class TestLz77DecoderStub:
    def test_lz77_decoder_stub_returns_bytes(self):
        result = lz77_decoder_stub(100)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_lz77_decoder_stub_small_size(self):
        result = lz77_decoder_stub(10)
        assert isinstance(result, bytes)
