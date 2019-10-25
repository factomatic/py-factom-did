import pytest

from factom_did.client.constants import DID_METHOD_NAME
from factom_did.client.did import DID, KeyType
from factom_did.client.keys.management import ManagementKey


@pytest.fixture
def did():
    return DID()


class TestManagementKeys:
    def test_add_management_keys(self, did):
        management_key_1_alias = "management-key-1"
        management_key_1_priority = 1
        did.management_key(management_key_1_alias, management_key_1_priority)
        generated_management_key_1 = did.management_keys[0]

        assert management_key_1_alias == generated_management_key_1.alias
        assert management_key_1_priority == generated_management_key_1.priority
        assert KeyType.EdDSA == generated_management_key_1.key_type
        assert did.id == generated_management_key_1.controller
        assert generated_management_key_1.public_key is not None
        assert generated_management_key_1.private_key is not None

        management_key_2_alias = "management-key-2"
        management_key_2_priority = 2
        management_key_2_type = KeyType.ECDSA
        management_key_2_controller = "{}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005".format(
            DID_METHOD_NAME
        )

        did.management_key(
            management_key_2_alias,
            management_key_2_priority,
            management_key_2_type,
            management_key_2_controller,
        )
        generated_management_key_2 = did.management_keys[1]

        assert management_key_2_alias == generated_management_key_2.alias
        assert management_key_2_priority == generated_management_key_2.priority
        assert management_key_2_type == generated_management_key_2.key_type
        assert management_key_2_controller == generated_management_key_2.controller
        assert generated_management_key_2.public_key is not None
        assert generated_management_key_2.private_key is not None

        management_key_3_alias = "management-key-3"
        management_key_3_priority = 3
        management_key_3_type = KeyType.RSA

        did.management_key(
            management_key_3_alias, management_key_3_priority, management_key_3_type
        )
        generated_management_key_3 = did.management_keys[2]

        assert management_key_3_alias == generated_management_key_3.alias
        assert management_key_3_priority == generated_management_key_3.priority
        assert management_key_3_type == generated_management_key_3.key_type
        assert did.id == generated_management_key_3.controller
        assert generated_management_key_3.public_key is not None
        assert generated_management_key_3.private_key is not None
        assert 3 == len(did.management_keys)

    def test_invalid_alias_throws_exception(self, did):
        test_cases = ["myManagementKey", "my-m@nagement-key", "my_management_key"]
        for alias in test_cases:
            with pytest.raises(ValueError):
                did.management_key(alias, 1)

    def test_invalid_priority_throws_exception(self, did):
        test_cases = [-1, -2]
        for priority in test_cases:
            management_key_alias = "management-key-{}".format(str(priority))
            with pytest.raises(ValueError):
                did.management_key(management_key_alias, priority)

    def test_used_alias_throws_exception(self, did):
        management_key_alias = "management-key-1"
        did.management_key(management_key_alias, 1)
        with pytest.raises(ValueError):
            did.management_key(management_key_alias, 1)

    def test_invalid_key_type_throws_exception(self, did):
        management_key_alias = "management-key"
        management_key_type = "invalid_key_type"
        with pytest.raises(ValueError):
            did.management_key(management_key_alias, 1, management_key_type)

    def test_invalid_controller_throws_exception(self, did):
        test_cases = [
            (
                "management-key-1",
                "{}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654h05f838b8005".format(
                    DID_METHOD_NAME
                ),
            ),
            (
                "management-key-2",
                "did:fctr:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005",
            ),
            (
                "management-key-3",
                "{}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b800".format(
                    DID_METHOD_NAME
                ),
            ),
        ]

        for alias, controller in test_cases:
            with pytest.raises(ValueError):
                did.management_key(alias, 1, KeyType.EdDSA, controller)

    def test__repr__method(self, did):
        management_key_alias = "management-key-1"
        management_key_priority = 0

        did.management_key(management_key_alias, management_key_priority)
        generated_management_key = did.management_keys[0]

        expected__repr__method_output = (
            "<{}.{}(alias={}, priority={}, key_type={},"
            " controller={}, priority_requirement={})>".format(
                ManagementKey.__module__,
                ManagementKey.__name__,
                management_key_alias,
                management_key_priority,
                generated_management_key.underlying,
                generated_management_key.controller,
                None,
            )
        )

        assert str(generated_management_key) == expected__repr__method_output

    def test__repr__method_with_rsa_key(self, did):
        management_key_alias = "management-key-1"
        management_key_priority = 0
        management_key_type = KeyType.RSA

        did.management_key(
            management_key_alias, management_key_priority, management_key_type
        )
        generated_management_key = did.management_keys[0]

        expected__repr__method_output = (
            "<{}.{}(alias={}, priority={}, key_type={},"
            " controller={}, priority_requirement={})>".format(
                ManagementKey.__module__,
                ManagementKey.__name__,
                management_key_alias,
                management_key_priority,
                generated_management_key.underlying,
                generated_management_key.controller,
                None,
            )
        )

        assert str(generated_management_key) == expected__repr__method_output
