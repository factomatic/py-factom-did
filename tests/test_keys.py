import secrets

import pytest

from client.constants import DID_METHOD_NAME
from client.enums import SignatureType
from client.keys import AbstractDIDKey, ManagementKey


@pytest.fixture
def controller():
    return "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))


class TestAbstractDIDKey:
    def test_initialization_with_given_keys(self, controller):
        with pytest.raises(ValueError) as excinfo:
            AbstractDIDKey(
                alias="test-key",
                signature_type=SignatureType.EdDSA.value,
                controller=controller,
                priority_requirement=1,
                public_key=None,
                private_key=b"012afaf",
            )
        assert (
            str(excinfo.value)
            == "Both private key and public key must be specified, or both must be unspecified"
        )

        with pytest.raises(ValueError) as excinfo:
            AbstractDIDKey(
                alias="test-key",
                signature_type=SignatureType.EdDSA.value,
                controller=controller,
                priority_requirement=1,
                public_key=b"012afaf",
                private_key=None,
            )
        assert (
            str(excinfo.value)
            == "Both private key and public key must be specified, or both must be unspecified"
        )

        AbstractDIDKey(
            alias="test-key",
            signature_type=SignatureType.EdDSA.value,
            controller=controller,
            priority_requirement=1,
            public_key=b"af01411",
            private_key=b"012afaf",
        )

    def test_equality(self, controller):
        key1 = AbstractDIDKey(
            alias="test-key",
            signature_type=SignatureType.EdDSA.value,
            controller=controller,
            priority_requirement=1,
            public_key=b"af01411",
            private_key=b"012afaf",
        )
        key2 = AbstractDIDKey(
            alias="test-key",
            signature_type=SignatureType.EdDSA.value,
            controller=controller,
            priority_requirement=1,
            public_key=b"af01411",
            private_key=b"012afaf",
        )
        key3 = ManagementKey(
            alias="test-key",
            signature_type=SignatureType.EdDSA.value,
            controller=controller,
            priority_requirement=1,
            priority=0,
            public_key=b"af01411",
            private_key=b"012afaf",
        )
        key4 = AbstractDIDKey(
            alias="test-key-2",
            signature_type=SignatureType.EdDSA.value,
            controller=controller,
            priority_requirement=1,
            public_key=b"af01411",
            private_key=b"012afaf",
        )
        assert key1 == key2
        assert key1.__eq__(key3) == NotImplemented
        assert key1 != key4

    def test_signing_and_verification(self, controller):
        ecdsa_key = AbstractDIDKey(
            alias="test-key",
            signature_type=SignatureType.ECDSA.value,
            controller=controller,
            priority_requirement=1,
        )
        eddsa_key = AbstractDIDKey(
            alias="test-key",
            signature_type=SignatureType.EdDSA.value,
            controller=controller,
            priority_requirement=1,
        )
        rsa_key = AbstractDIDKey(
            alias="test-key",
            signature_type=SignatureType.RSA.value,
            controller=controller,
            priority_requirement=1,
        )
        keys = [ecdsa_key, eddsa_key, rsa_key]
        invalid_message = "hello-DIDs"
        message = b"hello-DIDs"

        for key in keys:
            with pytest.raises(AssertionError):
                key.sign(invalid_message)

            sig = key.sign(message)
            assert key.verify(message, sig)
            assert not key.verify(b"hello", sig)

            with pytest.raises(AssertionError):
                key.verify(message.hex(), sig)
            with pytest.raises(AssertionError):
                key.verify(message, sig.hex())
