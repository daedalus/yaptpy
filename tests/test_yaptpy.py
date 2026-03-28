import pytest
from hypothesis import Verbosity, given, settings
from hypothesis import strategies as st

from yaptpy import (
    generate_payload,
    generate_polymorphic_junk,
    remove_comments_from_assembly,
    rle_decoder_stub,
    rle_encode,
    rolling_xor_decoder_stub,
    rolling_xor_encrypt,
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
