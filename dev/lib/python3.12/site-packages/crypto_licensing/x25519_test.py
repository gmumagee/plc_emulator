import pytest

from . import ed25519, x25519


def test_ecdh():
    sk1			= x25519.curve25519_key()
    sk2			= x25519.curve25519_key()
    assert x25519.curve25519(sk1, x25519.curve25519(sk2)) == x25519.curve25519(sk2, x25519.curve25519(sk1))


def test_multiparty_ecdh():
    """
    Simulate three-party ECDH exchange starting with Ed25519 keys
    Returns the shared secret computed by all parties
    """
    # Create participants with Ed25519 keys; all Ed25519 public keys are added to desired
    desired		= set()
    alice		= x25519.ECDH( ed25519.crypto_sign_keypair(), desired )
    bob			= x25519.ECDH( ed25519.crypto_sign_keypair(), desired )
    carol		= x25519.ECDH( ed25519.crypto_sign_keypair(), desired )

    # For demonstration, show original Ed25519 private keys
    print("Original Ed25519 private+public keys (hex):")
    print(f"Alice: {alice.ed25519_private.hex()}")
    print(f"Bob:   {bob.ed25519_private.hex()}")
    print(f"Carol: {carol.ed25519_private.hex()}")

    print("\nConverted X25519 private keys (int):")
    print(f"Alice: {alice.x25519_private}")
    print(f"Bob:   {bob.x25519_private}")
    print(f"Carol: {carol.x25519_private}")

    # Step 3: Alice -> Bob
    ag, ag_includes	= alice.initial_intermediate_value()
    assert ag_includes == {alice.ed25519_public}

    # Step 4: Bob -> Carol
    agb, agb_includes	= bob.compute_intermediate_value( ag, ag_includes )
    assert agb_includes == ag_includes | {bob.ed25519_public}

    # Step 5: Carol computes her secret
    agbc, agbc_includes	= carol.compute_final_secret( agb, agb_includes )
    carol_secret	= agbc
    assert agbc_includes == agb_includes | {carol.ed25519_public}

    # Step 6: Bob -> Carol
    bg, bg_includes	= bob.initial_intermediate_value()

    # Step 7: Carol -> Alice
    bgc, bgc_includes	= carol.compute_intermediate_value( bg, bg_includes )

    # Step 8: Alice computes her secret
    bgca, bgca_includes	= alice.compute_final_secret( bgc, bgc_includes )
    alice_secret	= bgca

    # Step 9: Carol -> Alice
    cg, cg_includes	= carol.initial_intermediate_value()
    assert cg_includes == {carol.ed25519_public}

    with pytest.raises(AssertionError, match=r"Intermediate value is missing keys: ([0-9a-f]+[,;]\s){2}should only"):
        # Can't compute final secret if it doesn't contain enough other keys (missing exactly 2)
        bob.compute_final_secret(cg, cg_includes)

    # Step 10: Alice -> Bob
    cga, cga_includes	= alice.compute_intermediate_value( cg, cg_includes )

    # Step 11: Bob computes his secret
    cgab, cgab_includes	= bob.compute_final_secret( cga, cga_includes )
    bob_secret		= cgab

    with pytest.raises(AssertionError, match="Intermediate value is missing keys: None; should only"):
        # Can't compute final secret if it already includes this key
        bob.compute_final_secret(cgab, cgab_includes)

    print("\nFinal shared secrets (int):")
    print(f"Alice: {alice_secret}")
    print(f"Bob:   {bob_secret}")
    print(f"Carol: {carol_secret}")

    secrets		= alice_secret, bob_secret, carol_secret

    # Verify all parties have the same secret
    assert all( s == secrets[0] for s in secrets[1:] ), "Shared secrets don't match!"
