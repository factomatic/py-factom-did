import hashlib
import secrets

import pytest
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

from factom_did.client.constants import DID_METHOD_NAME
from factom_did.client.enums import KeyType
from factom_did.client.keys.abstract import AbstractDIDKey
from factom_did.client.keys.management import ManagementKey


@pytest.fixture
def controller():
    return "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))


class TestAbstractDIDKey:
    def test_initialization_with_no_key(self, controller):
        AbstractDIDKey(
            alias="test-key",
            key_type=KeyType.EdDSA,
            controller=controller,
            priority_requirement=1,
        )

    def test_initialization_with_public_key_only(self, controller):
        AbstractDIDKey(
            alias="test-key",
            key_type=KeyType.EdDSA,
            controller=controller,
            priority_requirement=1,
            public_key=secrets.token_bytes(32),
        )

    def test_initialization_with_invalid_private_key(self, controller):
        with pytest.raises(ValueError) as excinfo:
            AbstractDIDKey(
                alias="test-key",
                key_type=KeyType.EdDSA,
                controller=controller,
                priority_requirement=1,
                private_key=b"012afaf",
            )
        assert (
            str(excinfo.value) == "Invalid Ed25519 private key. Must be a 32-byte seed."
        )

        with pytest.raises(ValueError) as excinfo:
            AbstractDIDKey(
                alias="test-key",
                key_type=KeyType.ECDSA,
                controller=controller,
                priority_requirement=1,
                private_key=b"012afaf",
            )
        assert (
            str(excinfo.value)
            == "Invalid ECDSA private key. Must be a 32-byte secret exponent."
        )

        with pytest.raises(ValueError) as excinfo:
            AbstractDIDKey(
                alias="test-key",
                key_type=KeyType.RSA,
                controller=controller,
                priority_requirement=1,
                private_key=b"012afaf",
            )
        assert str(excinfo.value) == "RSA key format is not supported"

    def test_initialization_with_valid_private_key(self, controller):
        AbstractDIDKey(
            alias="test-key",
            key_type=KeyType.EdDSA,
            controller=controller,
            priority_requirement=1,
            private_key=secrets.token_bytes(32),
        )

        AbstractDIDKey(
            alias="test-key",
            key_type=KeyType.ECDSA,
            controller=controller,
            priority_requirement=1,
            private_key=secrets.token_bytes(32),
        )

        AbstractDIDKey(
            alias="test-key",
            key_type=KeyType.RSA,
            controller=controller,
            priority_requirement=1,
            private_key=RSA.generate(2048).export_key("PEM"),
        )

        AbstractDIDKey(
            alias="test-key",
            key_type=KeyType.RSA,
            controller=controller,
            priority_requirement=1,
            private_key=RSA.generate(2048).export_key("PEM", pkcs=8),
        )

        AbstractDIDKey(
            alias="test-key",
            key_type=KeyType.RSA,
            controller=controller,
            priority_requirement=1,
            private_key=RSA.generate(2048).export_key("DER"),
        )

    def test_with_non_matching_public_key(self, controller):

        with pytest.raises(AssertionError) as excinfo:
            AbstractDIDKey(
                alias="test-key",
                key_type=KeyType.EdDSA,
                controller=controller,
                priority_requirement=1,
                private_key=secrets.token_bytes(32),
                public_key=b"asdfasdfasdfa",
            )
        assert (
            str(excinfo.value)
            == "The provided public key does not match the one derived from the provided private key"
        )

        with pytest.raises(AssertionError) as excinfo:
            AbstractDIDKey(
                alias="test-key",
                key_type=KeyType.ECDSA,
                controller=controller,
                priority_requirement=1,
                private_key=secrets.token_bytes(32),
                public_key=b"asdfasdfasdfa",
            )
        assert (
            str(excinfo.value)
            == "The provided public key does not match the one derived from the provided private key"
        )

        with pytest.raises(AssertionError) as excinfo:
            AbstractDIDKey(
                alias="test-key",
                key_type=KeyType.RSA,
                controller=controller,
                priority_requirement=1,
                private_key=RSA.generate(2048).export_key("PEM", pkcs=8),
                public_key=RSA.generate(2048).publickey().export_key(),
            )
        assert (
            str(excinfo.value)
            == "The provided public key does not match the one derived from the provided private key"
        )

    def test_equality(self, controller):
        private_key = secrets.token_bytes(32)
        key1 = AbstractDIDKey(
            alias="test-key",
            key_type=KeyType.EdDSA,
            controller=controller,
            priority_requirement=1,
            private_key=private_key,
        )
        key2 = AbstractDIDKey(
            alias="test-key",
            key_type=KeyType.EdDSA,
            controller=controller,
            priority_requirement=1,
            private_key=private_key,
        )
        key3 = ManagementKey(
            alias="test-key",
            key_type=KeyType.EdDSA,
            controller=controller,
            priority_requirement=1,
            priority=0,
            private_key=private_key,
        )
        key4 = AbstractDIDKey(
            alias="test-key-2",
            key_type=KeyType.EdDSA,
            controller=controller,
            priority_requirement=1,
            private_key=private_key,
        )
        assert key1 == key2
        assert key1.__eq__(key3) == NotImplemented
        assert key1 != key4

    def test_signing_and_verification(self, controller):
        ecdsa_key = AbstractDIDKey(
            alias="test-key",
            key_type=KeyType.ECDSA,
            controller=controller,
            priority_requirement=1,
        )
        eddsa_key = AbstractDIDKey(
            alias="test-key",
            key_type=KeyType.EdDSA,
            controller=controller,
            priority_requirement=1,
        )
        rsa_key = AbstractDIDKey(
            alias="test-key",
            key_type=KeyType.RSA,
            controller=controller,
            priority_requirement=1,
        )
        keys = [ecdsa_key, eddsa_key, rsa_key]
        hash_fs = [hashlib.sha256, hashlib.sha256, SHA256.new]
        invalid_message = "hello-DIDs"
        message = b"hello-DIDs"

        for key, hash_f in zip(keys, hash_fs):
            with pytest.raises(AssertionError):
                key.sign(invalid_message, hash_f)

            sig = key.sign(message, hash_f)
            assert key.verify(message, sig, hash_f)
            assert not key.verify(b"hello", sig, hash_f)

            with pytest.raises(AssertionError):
                key.verify(message.hex(), sig, hash_f)
            with pytest.raises(AssertionError):
                key.verify(message, sig.hex(), hash_f)
