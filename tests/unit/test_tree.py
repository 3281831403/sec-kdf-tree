"""Ten contract tests, one for each defect in README order."""

import hashlib
import hmac
import secrets

import pytest

from kdf.tree import (
    DEFAULT_SALT,
    MAX_LENGTH,
    derive,
    derive_key,
    expand,
    extract,
    kdf_batch,
    split,
    validate_policy,
    verify_derivation,
)

SECRET_A = bytes(range(16))
SECRET_B = bytes.fromhex("f0e0d0c0b0a090807060504030201000")
SALT = b"tenant-salt-v1"
IKM = b"master-ikm-2026"
PRK = bytes.fromhex(
    "101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f"
)
INFO = b"payments"
CONTEXT_A = b"payments"
CONTEXT_B = b"ledger"
PURPOSE_A = b"encrypt"
PURPOSE_B = b"decrypt"

EXTRACT_SALT = bytes.fromhex(
    "3f897cce44df539db5dda25de7e1d3f21d5583ad63e44d30b78329176872854b"
)
EXTRACT_EMPTY = bytes.fromhex(
    "745cd0b4e598b6b8cb52f0cd21b3c7b158ffb271f65850eb68d53eedc67810c8"
)
EMPTY_KEY_HMAC = bytes.fromhex(
    "b550f4661d489ab516dc1ef4a2dd85b4348cf6055ec9f30a44115f7c8693f32e"
)
EXPAND_64 = bytes.fromhex(
    "191c447812ea1a376690743a2a25f172ad9b4a8eeae25e77b30ed4a3b4dacdcf"
    "cc9babb6e6861af792fd850d365ab13e2b705295a7daaad0429efa48939fe0be"
)
EXPAND_96_A = bytes.fromhex(
    "d8433b827603201db875de2d6e51bf58d57f4d4a6199160b5baa845c8ed17fc9"
    "0fd0d1beda05b506dac41415c0a416d94b15354a4b285e4ef07ab4ffc4372079"
    "16bae58d43e2254ed1a62196f3f5db346ff9e1a8b73e03bd1aaeed2f4a485af9"
)
EXPAND_96_B = bytes.fromhex(
    "303e89552aee4f33abd6fdba991bfce33a87959a6e6a0e4b8c3bffd0db0e6902"
    "522058ebdf46c62b22e70042fcadd96a859cb6781f91be405c1c0e88915a4c05"
    "27c1fa1f47950ea991067922771b006d091169858367b2fdbf8e7a3780b342ad"
)
DERIVE_48 = bytes.fromhex(
    "24bd9b510c2c5082ed05004acd18cf9e59c364bbce604bc4492de6f19891ed1b"
    "a9852e2993ca0592aacbcfd4f8fccc26"
)
DERIVE_KEY_48 = bytes.fromhex(
    "59a6d135a8d8b91c7199c9def277d16b1a84ff08079c5e021fd3fbef44e63264"
    "25c3b9dd6408db69a2d3473a93428f98"
)
DERIVE_KEY_DECRYPT_48 = bytes.fromhex(
    "a71f06e1d790997c1a7fb17386a77965757f30afc4e516c3896c5e507b6f109e"
    "9131fb03291c03305715b8c75ac4bf59"
)
DERIVE_KEY_32 = bytes.fromhex(
    "59a6d135a8d8b91c7199c9def277d16b1a84ff08079c5e021fd3fbef44e63264"
)
SPLIT_ALPHA = bytes.fromhex(
    "d6cba6216d85951d24dbc378a52b5760dc3098ab659996dc7e4a83c12daeb8ff"
)
SPLIT_BETA = bytes.fromhex(
    "f1b121053ba5a4b434763234902ef236249859289414c3685169a77f82c4807e"
)
SPLIT_GAMMA = bytes.fromhex(
    "4192bf870620cdfba6bca91a2423d249fbf3da7f9d87f571a87999d05ea6e863"
)
BATCH_ALPHA_32 = bytes.fromhex(
    "152190f632f1c7a574bc74ea0e49029915763a3ee0e872927c3b35fb0bdd6494"
)
BATCH_BETA_64 = bytes.fromhex(
    "66d3892553947d6f7b467976d6e1d7df9a1c1c29c5ebb6736454c19e55510aed"
    "6dcbfc90aac99d7addbf36f3fe693fe59aa52126c144ec929c45dbb5d43fea0d"
)
MAX_TAIL = bytes.fromhex(
    "57e66137fe119ebea35806d9720018dfef2a76bac31ce7406f47f9f74afbfb4c"
)


def test_extract_uses_default_salt_when_salt_is_empty():
    assert DEFAULT_SALT == bytes(range(32))
    assert extract(SALT, IKM) == EXTRACT_SALT
    assert extract(b"", IKM) == EXTRACT_EMPTY
    assert extract(DEFAULT_SALT, IKM) == EXTRACT_EMPTY
    assert EXTRACT_EMPTY != EMPTY_KEY_HMAC


def test_expand_puts_counter_at_block_head():
    expanded = expand(PRK, INFO, 64)

    assert len(expanded) == 64
    assert expanded == EXPAND_64

    first = hmac.new(PRK, b"\x01" + INFO, hashlib.sha256).digest()
    second = hmac.new(
        PRK, b"\x02" + INFO + first, hashlib.sha256
    ).digest()

    assert expanded[:32] == first
    assert expanded[32:] == second


def test_expand_rejects_length_above_maximum():
    assert MAX_LENGTH == 8160

    maximum = expand(PRK, INFO, MAX_LENGTH)
    assert len(maximum) == MAX_LENGTH
    assert maximum[-32:] == MAX_TAIL

    with pytest.raises(ValueError):
        expand(PRK, INFO, MAX_LENGTH + 1)

    with pytest.raises(ValueError):
        expand(PRK, INFO, 10_000)


def test_expand_binds_info_in_every_block():
    first = expand(PRK, b"purpose-a", 96)
    second = expand(PRK, b"purpose-b", 96)

    assert first == EXPAND_96_A
    assert second == EXPAND_96_B
    assert first[:32] != second[:32]
    assert first[32:64] != second[32:64]
    assert first[64:96] != second[64:96]


def test_derive_key_separates_purpose():
    encrypted = derive_key(SECRET_A, CONTEXT_A, PURPOSE_A, 48)
    decrypted = derive_key(SECRET_A, CONTEXT_A, PURPOSE_B, 48)

    assert encrypted == DERIVE_KEY_48
    assert decrypted == DERIVE_KEY_DECRYPT_48
    assert encrypted != decrypted


def test_derive_rejects_zero_length():
    with pytest.raises(ValueError):
        derive(SECRET_A, SALT, INFO, 0)

    with pytest.raises(ValueError):
        derive_key(SECRET_A, CONTEXT_A, PURPOSE_A, 0)

    with pytest.raises(ValueError):
        derive(SECRET_A, SALT, INFO, -1)


def test_split_does_not_reuse_first_block():
    derived = split(SECRET_A, [b"alpha", b"beta", b"gamma"])

    assert set(derived) == {b"alpha", b"beta", b"gamma"}
    assert all(isinstance(value, bytes) for value in derived.values())
    assert all(len(value) == 32 for value in derived.values())
    assert derived[b"alpha"] == SPLIT_ALPHA
    assert derived[b"beta"] == SPLIT_BETA
    assert derived[b"gamma"] == SPLIT_GAMMA

    values = list(derived.values())
    assert len(set(values)) == 3
    assert len({value[:16] for value in values}) == 3


def test_verify_derivation_uses_constant_time_compare(monkeypatch):
    import kdf.tree as tree

    calls = []

    def fake_compare(left, right):
        calls.append((left, right))
        return True

    original_compare = hmac.compare_digest
    monkeypatch.setattr(hmac, "compare_digest", fake_compare)
    monkeypatch.setattr(secrets, "compare_digest", fake_compare)

    for name, value in vars(tree).items():
        if value is original_compare:
            monkeypatch.setattr(tree, name, fake_compare)

    candidate = b"\x00" * 32

    assert (
        verify_derivation(SECRET_A, CONTEXT_A, PURPOSE_A, candidate) is True
    )
    assert len(calls) == 1

    left, right = calls[0]
    assert (left, right) == (DERIVE_KEY_32, candidate) or (left, right) == (
        candidate,
        DERIVE_KEY_32,
    )


def test_validate_policy_reports_empty_context():
    valid = {"length": 32, "context": b"tenant-a", "purpose": b"encrypt"}

    assert validate_policy(valid) == []
    assert validate_policy({**valid, "length": MAX_LENGTH + 1}) == [
        "length-above-limit"
    ]
    assert validate_policy({**valid, "context": b""}) == ["context-empty"]
    assert validate_policy({"length": 32, "context": b"tenant-a"}) == [
        "purpose-missing"
    ]
    assert validate_policy(
        {"length": MAX_LENGTH + 1, "context": b"", "purpose": b""}
    ) == [
        "length-above-limit",
        "context-empty",
        "purpose-missing",
    ]


def test_kdf_batch_keeps_requests_independent():
    policy = {"length": 16, "context": b"default", "purpose": b"default"}
    policy_before = dict(policy)
    requests = [
        {
            "id": "alpha",
            "secret": SECRET_A,
            "context": b"alpha",
            "purpose": b"encrypt",
            "length": 32,
        },
        {
            "id": "beta",
            "secret": SECRET_B,
            "context": b"beta",
            "purpose": b"decrypt",
            "length": 64,
        },
    ]

    result = kdf_batch(requests, policy)

    assert set(result) == {"alpha", "beta"}
    assert result["alpha"] == BATCH_ALPHA_32
    assert result["beta"] == BATCH_BETA_64
    assert len(result["alpha"]) == 32
    assert len(result["beta"]) == 64
    assert result["alpha"] != result["beta"]
    assert policy == policy_before