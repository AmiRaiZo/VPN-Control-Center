from vpn_manager.security.totp import totp_code


def test_totp_matches_rfc_6238_sha1_six_digit_vector():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp_code(secret, timestamp=59) == "287082"


def test_totp_rejects_invalid_seed():
    import pytest

    with pytest.raises(ValueError, match="Base32"):
        totp_code("not a base32 seed!")