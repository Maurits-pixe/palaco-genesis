"""PALACO v28 owner identity verifier adapter for v27 (DRAFT / HOLD).

Verifies canonical Ed25519-signed external session attestations and requires
independent live role/revocation/MFA policy. This is NOT an identity issuer,
a PALACO One connection, an account allocator or a production auth service.
"""
import base64
import binascii
import json
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from offline_stage import _canonical
from recovery_operations_cockpit_v25 import ID

SCHEMA = "palaco-owner-session-attestation/v28"
DOMAIN = b"PALACO-OWNER-SESSION-ATTESTATION-v28\x00"
TOKEN_FIELDS = frozenset(("claims", "signature_b64", "key_id"))
CLAIM_FIELDS = frozenset((
    "schema", "issuer", "audience", "subject", "session_id", "device_id",
    "issued_at", "not_before", "expires_at", "mfa_at", "auth_method",
    "scope", "roles",
))
ALLOWED_METHOD = "phishing-resistant-mfa"
MAX_TOKEN_LENGTH = 8192
MAX_LIFETIME_SECONDS = 600
MAX_MFA_AGE_SECONDS = 300


class OwnerIdentityError(ValueError):
    pass


def _b64(value, size):
    if type(value) is not str or len(value) > 180:
        raise OwnerIdentityError("INVALID_SIGNATURE")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise OwnerIdentityError("INVALID_SIGNATURE") from exc
    if len(raw) != size or base64.b64encode(raw).decode("ascii") != value:
        raise OwnerIdentityError("INVALID_SIGNATURE")
    return raw


def _identity(value):
    if type(value) is not str or not ID.fullmatch(value):
        raise OwnerIdentityError("INVALID_IDENTITY")


class OwnerIdentityAdapter:
    """Callable verify_session(assertion, action, day) for v27.

    trust_key(key_id, claims) must independently authenticate issuer key
    lifecycle and current key revocation/scope, returning literal True.
    check_current_owner(subject, session_id, device_id, action, day)
    must query current authoritative roles, MFA and device/session revocation.
    trusted_now() must provide a trusted UTC epoch-seconds integer.
    None of these services is implemented by this adapter.
    """

    def __init__(self, *, issuer, audience, pinned_public_keys, trust_key,
                 check_current_owner, trusted_now):
        _identity(issuer)
        _identity(audience)
        if (type(pinned_public_keys) is not dict or not pinned_public_keys or
                not all(callable(x) for x in (
                    trust_key, check_current_owner, trusted_now))):
            raise OwnerIdentityError("EXTERNAL_TRUST_REQUIRED")
        keys = {}
        for key_id, value in pinned_public_keys.items():
            _identity(key_id)
            if type(value) is not bytes or len(value) != 32:
                raise OwnerIdentityError("INVALID_PUBLIC_KEY")
            keys[key_id] = value
        self.issuer, self.audience = issuer, audience
        self.keys = keys
        self.trust_key = trust_key
        self.check_current_owner = check_current_owner
        self.trusted_now = trusted_now

    def __call__(self, assertion, action, day):
        """Return owner ID or None. All invalid/unavailable trust fails closed."""
        try:
            if (type(assertion) is not str or
                    not 1 <= len(assertion) <= MAX_TOKEN_LENGTH or
                    type(action) is not str or action != "OWNER_REVIEW" or
                    type(day) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day)):
                return None
            data = json.loads(assertion)
            if (type(data) is not dict or set(data) != TOKEN_FIELDS or
                    _canonical(data).decode("ascii") != assertion):
                return None
            claim = data["claims"]
            if type(claim) is not dict or set(claim) != CLAIM_FIELDS:
                return None
            for field in ("issuer", "audience", "subject", "session_id", "device_id"):
                _identity(claim[field])
            _identity(data["key_id"])
            if claim["issuer"] != self.issuer or claim["audience"] != self.audience:
                return None
            if data["key_id"] not in self.keys or claim["schema"] != SCHEMA:
                return None
            if (type(claim["scope"]) is not str or claim["scope"] != action or
                    type(claim["roles"]) is not list or claim["roles"] != ["OWNER"] or
                    claim["auth_method"] != ALLOWED_METHOD):
                return None
            times = tuple(claim[k] for k in (
                "issued_at", "not_before", "expires_at", "mfa_at"))
            if any(type(n) is not int for n in times):
                return None
            issued, not_before, expires, mfa_at = times
            now = self.trusted_now()
            if type(now) is not int or not 1_700_000_000 <= now <= 4_102_444_800:
                return None
            if not (issued <= not_before <= now < expires and
                    0 < expires - issued <= MAX_LIFETIME_SECONDS and
                    issued <= mfa_at <= now and
                    0 <= now - mfa_at <= MAX_MFA_AGE_SECONDS):
                return None
            # Strict signed bytes; never accept unsigned identity fields.
            statement = DOMAIN + _canonical(claim)
            signature = _b64(data["signature_b64"], 64)
            Ed25519PublicKey.from_public_bytes(
                self.keys[data["key_id"]]).verify(signature, statement)
            if self.trust_key(data["key_id"], claim) is not True:
                return None
            if self.check_current_owner(
                    claim["subject"], claim["session_id"], claim["device_id"],
                    action, day) is not True:
                return None
            return claim["subject"]
        except Exception:
            # Invalid/expired/revoked sessions, unavailable independent
            # services, bad signatures and malformed claims all deny.
            return None
