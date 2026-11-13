"""RFC 8907 sec. 4.1 header codec."""

from __future__ import annotations

import pytest

from tacacs.header import (
    Header,
    HeaderError,
    PacketType,
    check_header,
    decode_header,
    encode_header,
    new_session_id,
)


def make(**changes):
    fields = {
        "major": 0xC,
        "minor": 0,
        "type": PacketType.AUTHEN,
        "seq_no": 1,
        "flags": 0,
        "session_id": 7,
        "length": 16,
    }
    fields.update(changes)
    return Header(**fields)


def test_decode_authen_start_header():
    raw = bytes.fromhex("c0 01 01 00 0badcafe 00000010")
    h = decode_header(raw)
    assert (h.major, h.minor, h.type, h.seq_no, h.session_id, h.length) == (
        12, 0, PacketType.AUTHEN, 1, 0x0BADCAFE, 16,
    )  # fmt: skip
    assert h.flags == 0


def test_encode_header_matches_hand_built_octets():
    assert encode_header(make(session_id=0x0BADCAFE)) == bytes.fromhex("c00101000badcafe00000010")


@pytest.mark.parametrize("minor", [0, 1])
@pytest.mark.parametrize("kind", list(PacketType))
@pytest.mark.parametrize("flags", [0, 1, 4, 5])
def test_round_trip(minor, kind, flags):
    h = make(minor=minor, type=kind, flags=flags)
    assert decode_header(encode_header(h)) == h


def test_version_byte_c1_is_minor_one():
    assert decode_header(bytes.fromhex("c1 02 03 00 00000001 00000000")).minor == 1
    assert make(minor=1).version_byte == 0xC1


@pytest.mark.parametrize("size", range(12))
def test_short_header_refused(size):
    with pytest.raises(HeaderError):
        decode_header(bytes(size))


def test_trailing_bytes_ignored_by_decode():
    raw = bytes.fromhex("c0 01 01 00 0badcafe 00000010") + b"body"
    assert decode_header(raw).length == 16


def test_unknown_flag_bits_ignored_on_read_and_not_written():
    h = decode_header(bytes.fromhex("c0 01 01 f2 00000001 00000000"))
    assert not h.unencrypted
    assert not h.single_connect
    assert encode_header(make(flags=0xF2))[3] == 0x00


def test_check_header_accepts_a_good_client_and_server_header():
    check_header(make(seq_no=1), from_client=True)
    check_header(make(seq_no=2), from_client=False)


def test_check_header_rejects_wrong_major():
    with pytest.raises(HeaderError):
        check_header(make(major=0xB), from_client=True)


def test_check_header_rejects_unknown_minor_and_type():
    with pytest.raises(HeaderError):
        check_header(make(minor=2), from_client=True)
    with pytest.raises(HeaderError):
        check_header(
            decode_header(bytes.fromhex("c0 09 01 00 00000001 00000000")), from_client=True
        )


def test_check_header_rejects_seq_zero():
    with pytest.raises(HeaderError):
        check_header(make(seq_no=0), from_client=True)
    with pytest.raises(HeaderError):
        check_header(make(seq_no=0), from_client=False)


def test_client_even_seq_refused():
    with pytest.raises(HeaderError):
        check_header(make(seq_no=2), from_client=True)


def test_server_odd_seq_refused():
    with pytest.raises(HeaderError):
        check_header(make(seq_no=3), from_client=False)


def test_length_over_limit_refused():
    check_header(make(length=65536), from_client=True)
    with pytest.raises(HeaderError):
        check_header(make(length=65537), from_client=True)
    check_header(make(length=100000), from_client=True, max_length=200000)


def test_length_at_u32_max_refused_without_allocating():
    h = decode_header(bytes.fromhex("c0 01 01 00 00000001 ffffffff"))
    assert h.length == 0xFFFFFFFF
    with pytest.raises(HeaderError):
        check_header(h, from_client=True)


def test_encode_refuses_out_of_range_values():
    for bad in (
        {"seq_no": 256},
        {"session_id": 2**32},
        {"length": 2**32},
        {"minor": 16},
        {"seq_no": -1},
    ):
        with pytest.raises(HeaderError):
            encode_header(make(**bad))


def test_session_id_is_not_constant():
    assert len({new_session_id() for _ in range(100)}) > 90


def test_unencrypted_flag_is_representable():
    h = decode_header(bytes.fromhex("c0 01 01 01 00000001 00000000"))
    assert h.unencrypted
    check_header(h, from_client=True)  # policy lives elsewhere (RFC 9887 sec. 4 needs it)
    assert encode_header(h)[3] == 0x01
