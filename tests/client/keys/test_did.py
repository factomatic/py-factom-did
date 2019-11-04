import pytest

from factom_did.client.constants import DID_METHOD_NAME
from factom_did.client.did import DID, DIDKeyPurpose, KeyType
from factom_did.client.keys.did import DIDKey


@pytest.fixture
def did():
    return DID()


class TestDidKeys:
    def test_add_did_keys(self, did):
        did_key_1_alias = "did-key-1"
        did_key_1_purpose = [DIDKeyPurpose.PublicKey]
        did.did_key(did_key_1_alias, did_key_1_purpose)
        generated_did_key_1 = did.did_keys[0]

        assert did_key_1_alias == generated_did_key_1.alias
        assert did_key_1_purpose == generated_did_key_1.purpose
        assert KeyType.EdDSA == generated_did_key_1.key_type
        assert did.id == generated_did_key_1.controller
        assert generated_did_key_1.priority_requirement is None

        did_key_2_alias = "did-key-2"
        did_key_2_purpose = [DIDKeyPurpose.PublicKey, DIDKeyPurpose.AuthenticationKey]
        did_key_2_type = KeyType.ECDSA
        did_key_2_controller = "{}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005".format(
            DID_METHOD_NAME
        )
        did_key_2_priority_requirement = 1
        did.did_key(
            did_key_2_alias,
            did_key_2_purpose,
            did_key_2_type,
            did_key_2_controller,
            did_key_2_priority_requirement,
        )
        generated_did_key_2 = did.did_keys[1]

        assert did_key_2_alias == generated_did_key_2.alias
        assert did_key_2_purpose == generated_did_key_2.purpose
        assert did_key_2_type == generated_did_key_2.key_type
        assert did_key_2_controller == generated_did_key_2.controller
        assert (
            did_key_2_priority_requirement == generated_did_key_2.priority_requirement
        )
        assert 2 == len(did.did_keys)

    def test_invalid_alias_throws_exception(self, did):
        test_cases = ["myDidKey", "my-d!d-key", "my_did_key"]
        for alias in test_cases:
            with pytest.raises(ValueError):
                did.did_key(alias, [DIDKeyPurpose.PublicKey])

    def test_invalid_purpose_type_throws_exception(self, did):
        did_key_alias = "did-key"
        did_key_purpose = [DIDKeyPurpose.PublicKey, "InvalidPurposeType"]
        with pytest.raises(ValueError):
            did.did_key(did_key_alias, did_key_purpose)

    def test_used_alias_throws_exception(self, did):
        alias = "my-key-1"
        did.management_key(alias, 1)
        with pytest.raises(ValueError):
            did.did_key(alias, [DIDKeyPurpose.PublicKey])

    def test_invalid_key_type_throws_exception(self, did):
        did_key_alias = "management-key"
        did_key_type = "invalid_key_type"
        with pytest.raises(ValueError):
            did.did_key(did_key_alias, [DIDKeyPurpose.PublicKey], did_key_type)

    def test_invalid_controller_throws_exception(self, did):
        test_cases = [
            (
                "did-key-1",
                "did:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005",
            ),
            (
                "did-key-2",
                "did:fctr:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b800",
            ),
        ]

        for alias, controller in test_cases:
            with pytest.raises(ValueError):
                did.did_key(alias, [DIDKeyPurpose.PublicKey], KeyType.EdDSA, controller)

    def test_invalid_priority_requirement_throws_exception(self, did):
        test_cases = [-1, -2]
        for priority_requirement in test_cases:
            did_key_alias = "did-key-{}".format(str(priority_requirement))
            with pytest.raises(ValueError):
                did.did_key(
                    did_key_alias,
                    [DIDKeyPurpose.PublicKey],
                    KeyType.EdDSA,
                    None,
                    priority_requirement,
                )

    def test_duplicate_purposes_throws_exception(self, did):
        with pytest.raises(AssertionError):
            did_key_alias = "did-key-1"
            did.did_key(
                did_key_alias,
                [DIDKeyPurpose.PublicKey, DIDKeyPurpose.PublicKey],
                KeyType.ECDSA,
                None,
            )

        with pytest.raises(AssertionError):
            did_key_alias = "did-key-1"
            did.did_key(
                did_key_alias,
                [
                    DIDKeyPurpose.PublicKey,
                    DIDKeyPurpose.AuthenticationKey,
                    DIDKeyPurpose.AuthenticationKey,
                ],
                KeyType.ECDSA,
                None,
            )

    def test__repr__method(self, did):
        did_key_alias = "did-key-1"
        did_key_purpose = [DIDKeyPurpose.PublicKey]
        did_key_type = KeyType.EdDSA
        did_key_controller = "{}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005".format(
            DID_METHOD_NAME
        )
        did_key_priority_requirement = 1

        did.did_key(
            did_key_alias,
            did_key_purpose,
            did_key_type,
            did_key_controller,
            did_key_priority_requirement,
        )
        generated_did_key = did.did_keys[0]

        expected__repr__method_output = (
            "<{}.{}(alias={}, purpose={}, key_type={},"
            " controller={}, priority_requirement={})>".format(
                DIDKey.__module__,
                DIDKey.__name__,
                did_key_alias,
                did_key_purpose,
                generated_did_key.underlying,
                did_key_controller,
                did_key_priority_requirement,
            )
        )

        assert str(generated_did_key) == expected__repr__method_output

    def test__repr__method_with_rsa_key(self, did):
        did_key_alias = "did-key-1"
        did_key_purpose = [DIDKeyPurpose.PublicKey, DIDKeyPurpose.AuthenticationKey]
        did_key_type = KeyType.RSA

        did.did_key(did_key_alias, did_key_purpose, did_key_type)
        generated_did_key = did.did_keys[0]

        expected__repr__method_output = (
            "<{}.{}(alias={}, purpose={}, key_type={},"
            " controller={}, priority_requirement={})>".format(
                DIDKey.__module__,
                DIDKey.__name__,
                did_key_alias,
                did_key_purpose,
                generated_did_key.underlying,
                generated_did_key.controller,
                None,
            )
        )

        assert str(generated_did_key) == expected__repr__method_output
