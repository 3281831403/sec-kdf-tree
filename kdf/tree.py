"""Contracts for a domain-separated two-stage key derivation tree.

The module has no running implementation. Each of the eight public functions
below is a contract stub and currently raises NotImplementedError.

Constants
---------
DEFAULT_SALT is the mandatory replacement for an empty extraction salt. It is
the 32 bytes 0x00 through 0x1f, not an empty key:

    DEFAULT_SALT = bytes(range(32))

MAX_LENGTH is 255 SHA-256 blocks:

    MAX_LENGTH = 255 * 32 = 8160

Domain encoding
---------------
derive_key encodes the business context and the purpose as:

    PREFIX
    + len(context).to_bytes(2, "big")
    + context
    + len(purpose).to_bytes(2, "big")
    + purpose

PREFIX is b"GSB-KDF-TREE-v1". Both context and purpose must be non-empty bytes,
each at most 65535 bytes, and both must participate in every output block.

Extraction and expansion
------------------------
extract uses HMAC-SHA256 with the supplied salt, replacing an empty salt with
DEFAULT_SALT before keying the HMAC.

expand builds SHA-256 HMAC blocks from a pseudorandom key. For i = 1 .. n,
where n is ceil(length / 32), the exact block input is:

    bytes([i]) + info + previous_block

with previous_block empty for the first block. The single-byte counter comes
first, info participates in every block, and the concatenated blocks are
truncated to exactly length bytes. Outputs longer than MAX_LENGTH are rejected,
never silently truncated.

All functions are deterministic and must not depend on randomness, clocks,
environment variables, process-global mutable state or network access.
"""

import hashlib
import hmac

MAX_LENGTH = 255 * 32
DEFAULT_SALT = bytes(range(32))
PREFIX = b"GSB-KDF-TREE-v1"
SPLIT_PURPOSE = b"split"

_MAX_FIELD_BYTES = 65535


def _validate_length(length: int) -> None:
    """Reject any length outside the inclusive 1..MAX_LENGTH range."""
    if isinstance(length, bool) or not isinstance(length, int):
        raise ValueError("length must be an int in 1..MAX_LENGTH")
    if length < 1 or length > MAX_LENGTH:
        raise ValueError("length must be in 1..MAX_LENGTH")


def _validate_domain_field(value: bytes, name: str) -> None:
    """Validate a non-empty bytes domain-separation field."""
    if not isinstance(value, bytes):
        raise ValueError(f"{name} must be bytes")
    if len(value) == 0:
        raise ValueError(f"{name} must be non-empty")
    if len(value) > _MAX_FIELD_BYTES:
        raise ValueError(f"{name} must be at most 65535 bytes")


def extract(salt: bytes, ikm: bytes) -> bytes:
    """Extract a 32-byte pseudorandom key from input keying material.

    If salt is b"", use DEFAULT_SALT as the HMAC key. If salt is non-empty, use
    it unchanged. The result is exactly:

        HMAC-SHA256(key=effective_salt, msg=ikm).digest()

    The default salt must be a real non-empty salt. Skipping extraction,
    returning ikm itself, or keying the HMAC with b"" is invalid. The result is
    always 32 bytes and identical inputs always return identical bytes.
    """
    # Defect 1 fix: an empty salt selects the mandatory default salt instead
    # of being passed through as an empty HMAC key / skipping extraction.
    effective_salt = DEFAULT_SALT if salt == b"" else salt
    return hmac.new(effective_salt, ikm, hashlib.sha256).digest()


def expand(prk: bytes, info: bytes, length: int) -> bytes:
    """Expand a pseudorandom key into exactly length deterministic bytes.

    length must be an int in 1..MAX_LENGTH. A zero, negative or over-limit
    length raises ValueError. The 255-block upper bound must be checked before
    producing output; an over-limit request must never be silently truncated.

    For i = 1..ceil(length / 32), T_0 is b"" and:

        T_i = HMAC-SHA256(prk, bytes([i]) + info + T_(i-1))

    The counter byte is at the beginning of each block, and info is included in
    every block, including all blocks after the first. Return the concatenation
    of T_1 through T_n truncated to length bytes. Truncation must preserve the
    leading bytes of the final block exactly.
    """
    # Defect 3 fix: enforce the 255-block ceiling before producing anything,
    # so an over-limit request raises instead of being silently truncated.
    _validate_length(length)

    block_count = (length + hashlib.sha256().digest_size - 1) // 32
    blocks = []
    previous_block = b""
    for i in range(1, block_count + 1):
        # Defect 2 fix: the single-byte counter is the FIRST byte of the block.
        # Defect 4 fix: info is mixed into EVERY block, not only T_1.
        previous_block = hmac.new(
            prk,
            bytes([i]) + info + previous_block,
            hashlib.sha256,
        ).digest()
        blocks.append(previous_block)

    return b"".join(blocks)[:length]


def derive(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Run extraction and expansion as one deterministic two-stage operation.

    The operation is exactly:

        expand(extract(salt, secret), info, length)

    length must be positive and no greater than MAX_LENGTH. In particular,
    length == 0 must raise ValueError rather than returning b"". A negative or
    over-limit length also raises ValueError. The empty-salt default behavior
    belongs to extract and must apply here as well.
    """
    # Defect 6 fix: reject length <= 0 (and over-limit lengths) up front
    # instead of letting expand return an empty/truncated byte string.
    _validate_length(length)
    prk = extract(salt, secret)
    return expand(prk, info, length)


def derive_key(
    secret: bytes,
    context: bytes,
    purpose: bytes,
    length: int,
) -> bytes:
    """Derive one business key bound to both context and purpose.

    context and purpose must be non-empty bytes objects no longer than 65535
    bytes each. The encoded info is exactly:

        PREFIX
        + len(context).to_bytes(2, "big")
        + context
        + len(purpose).to_bytes(2, "big")
        + purpose

    Derive from secret with an empty salt, so extract applies DEFAULT_SALT:

        derive(secret, b"", encoded_info, length)

    Both context and purpose must change the resulting bytes. Omitting purpose
    from the encoded info, or using purpose only for the first block, is
    invalid. Invalid context, purpose or length raises ValueError.
    """
    _validate_domain_field(context, "context")
    _validate_domain_field(purpose, "purpose")
    _validate_length(length)

    # Defect 5 fix: purpose is length-prefixed and included in the encoded
    # info handed to expand, where it participates in every HMAC block.
    encoded_info = (
        PREFIX
        + len(context).to_bytes(2, "big")
        + context
        + len(purpose).to_bytes(2, "big")
        + purpose
    )
    return derive(secret, b"", encoded_info, length)


def split(secret: bytes, contexts: list[bytes]) -> dict:
    """Derive one independent 32-byte key per context.

    Each context is used exactly as:

        derive_key(secret, context, SPLIT_PURPOSE, 32)

    SPLIT_PURPOSE is b"split". Contexts must be non-empty bytes and must be
    unique; invalid, empty or duplicate contexts raise ValueError. Every value
    in the returned dict is exactly 32 bytes. Different contexts must produce
    different values, and no two values may share a reused first block or a
    common prefix caused by reusing the first derivation. Derivation for one
    context must not depend on the position of that context in the input.
    """
    derived: dict[bytes, bytes] = {}
    seen: set[bytes] = set()

    for context in contexts:
        _validate_domain_field(context, "context")
        if context in seen:
            raise ValueError(f"duplicate context: {context!r}")
        seen.add(context)

        # Defect 7 fix: every context gets a fresh, full derive_key call. No
        # first block / prefix is cached and shared across contexts.
        derived[context] = derive_key(secret, context, SPLIT_PURPOSE, 32)

    return derived


def verify_derivation(
    secret: bytes,
    context: bytes,
    purpose: bytes,
    candidate: bytes,
) -> bool:
    """Check a candidate against the expected 32-byte business key.

    The expected value is derive_key(secret, context, purpose, 32). Compare the
    candidate with hmac.compare_digest, or an equivalent standard-library
    constant-time comparison such as secrets.compare_digest. Do not use ordinary
    equality, because that leaks comparison timing.

    Return True only for an exact 32-byte match, and return False for a wrong
    value of any length. Invalid derivation parameters raise ValueError.
    """
    expected = derive_key(secret, context, purpose, 32)
    # Defect 8 fix: constant-time comparison instead of ordinary ``==``.
    # Return the comparison result directly; compare_digest itself returns
    # False when the lengths differ.
    return hmac.compare_digest(expected, candidate)


def validate_policy(policy: dict) -> list[str]:
    """Return policy problems in the documented fixed order.

    policy is a mapping with length, context and purpose entries. Return a list
    containing exactly the applicable strings in this order:

        "length-above-limit"
            policy["length"] is greater than MAX_LENGTH
        "context-empty"
            context is absent, None or b""
        "purpose-missing"
            purpose is absent, None or b""

    A valid policy returns an empty list. Checking context is mandatory: a
    policy with an empty context must never be reported as valid.
    """
    problems: list[str] = []

    if policy["length"] > MAX_LENGTH:
        problems.append("length-above-limit")

    # Defect 9 fix: context absence / None / b"" is reported, not skipped.
    context = policy.get("context")
    if context is None or context == b"":
        problems.append("context-empty")

    purpose = policy.get("purpose")
    if purpose is None or purpose == b"":
        problems.append("purpose-missing")

    return problems


def kdf_batch(requests: list[dict], policy: dict) -> dict:
    """Derive several independent business keys in one call.

    policy supplies default length, context and purpose values. Each request is
    a mapping with a unique id and secret, plus optional context, purpose and
    length overrides. Merge each request over a copy of policy, validate the
    merged values with validate_policy, and raise ValueError if any problem
    remains or an id is duplicated.

    For each request, return:

        result[id] = derive_key(secret, merged_context, merged_purpose,
                                merged_length)

    Every request must be derived from its own secret, context, purpose and
    length. No extraction result, expansion block or encoded info may be reused
    between requests; in particular, a later request must not inherit the first
    request's context. Inputs and policy must not be mutated. Empty requests
    returns an empty dict.
    """
    results: dict = {}
    seen_ids: set = set()

    for request in requests:
        request_id = request["id"]
        if request_id in seen_ids:
            raise ValueError(f"duplicate request id: {request_id!r}")
        seen_ids.add(request_id)

        # Defect 10 fix: start from a FRESH copy of the original policy for
        # every request, so overrides / encoded state from an earlier request
        # can never leak into a later one. policy itself is never mutated.
        merged = dict(policy)
        merged.update(request)

        problems = validate_policy(merged)
        if problems:
            raise ValueError(
                f"invalid merged policy for id {request_id!r}: "
                + ", ".join(problems)
            )

        # A brand-new derivation per request; no PRK, block or info cache.
        results[request_id] = derive_key(
            request["secret"],
            merged["context"],
            merged["purpose"],
            merged["length"],
        )

    return results