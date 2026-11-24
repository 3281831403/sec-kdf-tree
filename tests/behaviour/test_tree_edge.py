"""Five boundary tests for fixed vectors, determinism and batch isolation."""

import pytest

from kdf.tree import (
    MAX_LENGTH,
    derive,
    derive_key,
    expand,
    extract,
    kdf_batch,
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
EXPAND_96 = bytes.fromhex(
    "191c447812ea1a376690743a2a25f172ad9b4a8eeae25e77b30ed4a3b4dacdcf"
    "cc9babb6e6861af792fd850d365ab13e2b705295a7daaad0429efa48939fe0be"
    "aec0ce6e5c3900a7af88b66e0292b0aded134230afe44157ae17481b2eb922a7"
)
DERIVE_48 = bytes.fromhex(
    "24bd9b510c2c5082ed05004acd18cf9e59c364bbce604bc4492de6f19891ed1b"
    "a9852e2993ca0592aacbcfd4f8fccc26"
)
DERIVE_KEY_48 = bytes.fromhex(
    "59a6d135a8d8b91c7199c9def277d16b1a84ff08079c5e021fd3fbef44e63264"
    "25c3b9dd6408db69a2d3473a93428f98"
)
LEDGER_ENCRYPT_48 = bytes.fromhex(
    "f9aff5ad4f2b59b3d42441adb6a58c4481e7fdb785406ca8d1a3fef1739ab2a3"
    "0a92353b4892255e8017e79379e580a6"
)
BATCH_ALPHA_32 = bytes.fromhex(
    "152190f632f1c7a574bc74ea0e49029915763a3ee0e872927c3b35fb0bdd6494"
)
BATCH_BETA_64 = bytes.fromhex(
    "66d3892553947d6f7b467976d6e1d7df9a1c1c29c5ebb6736454c19e55510aed"
    "6dcbfc90aac99d7addbf36f3fe693fe59aa52126c144ec929c45dbb5d43fea0d"
)


def test_fixed_inputs_match_known_vectors():
    assert extract(SALT, IKM) == EXTRACT_SALT
    assert expand(PRK, INFO, 96) == EXPAND_96
    assert derive(SECRET_A, SALT, INFO, 48) == DERIVE_48
    assert derive_key(SECRET_A, CONTEXT_A, PURPOSE_A, 48) == DERIVE_KEY_48


def test_same_inputs_are_byte_stable():
    first = derive_key(SECRET_A, CONTEXT_A, PURPOSE_A, 48)
    second = derive_key(SECRET_A, CONTEXT_A, PURPOSE_A, 48)

    assert type(first) is bytes
    assert first == second == DERIVE_KEY_48
    assert derive(SECRET_A, SALT, INFO, 48) == derive(
        SECRET_A, SALT, INFO, 48
    )
    assert expand(PRK, INFO, 96) == expand(PRK, INFO, 96) == EXPAND_96


def test_different_contexts_produce_different_keys():
    payments = derive_key(SECRET_A, CONTEXT_A, PURPOSE_A, 48)
    ledger = derive_key(SECRET_A, CONTEXT_B, PURPOSE_A, 48)

    assert payments == DERIVE_KEY_48
    assert ledger == LEDGER_ENCRYPT_48
    assert payments != ledger
    assert payments[:16] != ledger[:16]


def test_overlong_requests_are_rejected():
    assert MAX_LENGTH == 8160

    with pytest.raises(ValueError):
        expand(PRK, INFO, MAX_LENGTH + 1)

    with pytest.raises(ValueError):
        derive(SECRET_A, SALT, INFO, MAX_LENGTH + 1)

    with pytest.raises(ValueError):
        derive_key(SECRET_A, CONTEXT_A, PURPOSE_A, MAX_LENGTH + 1)

    policy = {"length": 32, "context": b"default", "purpose": b"default"}
    with pytest.raises(ValueError):
        kdf_batch(
            [
                {
                    "id": "oversized",
                    "secret": SECRET_A,
                    "context": b"alpha",
                    "purpose": b"encrypt",
                    "length": MAX_LENGTH + 1,
                }
            ],
            policy,
        )

    assert len(derive(SECRET_A, SALT, INFO, MAX_LENGTH)) == MAX_LENGTH


def test_independent_batches_match_individual_derivations():
    policy = {"length": 16, "context": b"default", "purpose": b"default"}
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

    forward = kdf_batch(requests, policy)
    reverse = kdf_batch(list(reversed(requests)), policy)
    alone_alpha = kdf_batch([requests[0]], policy)
    alone_beta = kdf_batch([requests[1]], policy)

    assert forward == reverse
    assert forward["alpha"] == BATCH_ALPHA_32
    assert forward["beta"] == BATCH_BETA_64

    for request in requests:
        request_id = request["id"]
        expected = derive_key(
            request["secret"],
            request["context"],
            request["purpose"],
            request["length"],
        )
        assert forward[request_id] == expected
        assert reverse[request_id] == expected

    assert alone_alpha["alpha"] == forward["alpha"]
    assert alone_beta["beta"] == forward["beta"]