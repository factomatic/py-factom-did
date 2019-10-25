from factom_did.client.keys.rsa import RSAKey


class TestMinifyRSAPublicKey:
    def test_minify_rsa_public_key(self):
        rsa_key = RSAKey()
        minified_public_key = rsa_key._minify_public_key()
        assert len(minified_public_key) < len(rsa_key.public_key)
        assert len(minified_public_key) == 31
