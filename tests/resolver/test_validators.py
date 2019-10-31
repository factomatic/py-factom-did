import json
import secrets

from jsonschema.exceptions import ValidationError
import pytest

from factom_did.client.constants import DID_METHOD_NAME
from factom_did.client.enums import DIDKeyPurpose, KeyType
from factom_did.client.keys.did import DIDKey
from factom_did.client.keys.management import ManagementKey
from factom_did.client.service import Service
from factom_did.resolver.exceptions import MalformedDIDManagementEntry
from factom_did.resolver.schema import get_schema_validator
from factom_did.resolver.validators import (
    validate_did_deactivation_ext_ids_v100,
    validate_did_management_ext_ids_v100,
    validate_did_method_version_upgrade_ext_ids_v100,
    validate_did_update_ext_ids_v100,
    EmptyEntryContentValidator,
)


class TestDIDManagementEntryValidation:
    VALIDATOR = get_schema_validator("did_management_entry.json")

    def test_insufficient_extids(self):
        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_ext_ids_v100([b"DIDManagement"])
        assert str(excinfo.value) == "Invalid or missing DIDManagement entry ExtIDs"

    def test_malformed_extids(self):
        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_ext_ids_v100([b"DIdManagement", b"1.0.0"])
        assert str(excinfo.value) == "Invalid or missing DIDManagement entry ExtIDs"

        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_ext_ids_v100([b"DIDManagement", b"1.0.a"])
        assert str(excinfo.value) == "Invalid or missing DIDManagement entry ExtIDs"

        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_ext_ids_v100([b"DIDManagement", b"\xbb"])
        assert str(excinfo.value) == "Invalid or missing DIDManagement entry ExtIDs"

        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_ext_ids_v100([b"\xbb", b"1.0.0"])
        assert str(excinfo.value) == "Invalid or missing DIDManagement entry ExtIDs"

    def test_entry_with_missing_required_fields(self):
        with pytest.raises(ValidationError):
            self.VALIDATOR.validate({})

        missing_management_keys = json.dumps({"didMethodVersion": "0.2.0"})
        with pytest.raises(ValidationError):
            self.VALIDATOR.validate(missing_management_keys)

        did = "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))
        missing_did_method_version = {
            "managementKey": [
                ManagementKey(
                    alias="my-man-key",
                    controller=did,
                    key_type=KeyType.EdDSA,
                    priority=0,
                ).to_entry_dict(did)
            ]
        }
        with pytest.raises(ValidationError):
            self.VALIDATOR.validate(missing_did_method_version)

    def test_entry_with_invalid_did_method_version(self):
        did = "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))
        entry = {
            "didMethodVersion": "0.3.0",
            "managementKey": [
                ManagementKey(
                    alias="my-man-key-1",
                    controller=did,
                    key_type=KeyType.EdDSA,
                    priority=0,
                ).to_entry_dict(did),
                ManagementKey(
                    alias="my-man-key-2",
                    controller=did,
                    key_type=KeyType.RSA,
                    priority=1,
                ).to_entry_dict(did),
            ],
        }

        with pytest.raises(ValidationError):
            self.VALIDATOR.validate(entry)

    def test_valid_entry(self):
        did = "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))
        validate_did_management_ext_ids_v100([b"DIDManagement", b"1.0.0"])
        validate_did_management_ext_ids_v100(
            [b"DIDManagement", b"1.0.0", b"asdfasdfasdf"]
        )
        valid_entry = {
            "didMethodVersion": "0.2.0",
            "managementKey": [
                ManagementKey(
                    alias="my-man-key-1",
                    controller=did,
                    key_type=KeyType.EdDSA,
                    priority=0,
                ).to_entry_dict(did),
                ManagementKey(
                    alias="my-man-key-2",
                    controller=did,
                    key_type=KeyType.RSA,
                    priority=1,
                ).to_entry_dict(did),
            ],
            "didKey": [
                DIDKey(
                    alias="my-did-key",
                    controller=did,
                    key_type=KeyType.RSA.ECDSA,
                    purpose=DIDKeyPurpose.PublicKey,
                ).to_entry_dict(did)
            ],
            "service": [
                Service(
                    alias="gmail-service",
                    service_type="email-service",
                    endpoint="https://gmail.com",
                ).to_entry_dict(did)
            ],
        }
        self.VALIDATOR.validate(valid_entry)


class TestDIDUpdateEntryValidation:
    VALIDATOR = get_schema_validator("did_update_entry.json")

    def test_insufficient_extids(self):
        chain_id = secrets.token_hex(32)
        assert (
            validate_did_update_ext_ids_v100(
                [
                    b"DIDUpdate",
                    b"1.0.0",
                    "{}:{}#my-key".format(DID_METHOD_NAME, chain_id).encode("utf-8"),
                ],
                chain_id,
            )
            is False
        )

    def test_malformed_extids(self):
        chain_id = secrets.token_hex(32)
        key_id = "{}:{}#{}".format(DID_METHOD_NAME, chain_id, "my-man-key-1")

        assert (
            validate_did_update_ext_ids_v100(
                [b"DIdUpdate", b"1.0.0", key_id.encode("utf-8"), b"af01"], chain_id
            )
            is False
        )

        assert (
            validate_did_update_ext_ids_v100(
                [b"DIDUpdate", b"1.0.0", b"\xbb", b"af01"], chain_id
            )
            is False
        )

        assert (
            validate_did_update_ext_ids_v100(
                [b"DIDUpdate", b"1.0.", key_id.encode("utf-8"), b"af01"], chain_id
            )
            is False
        )

        assert (
            validate_did_update_ext_ids_v100(
                [
                    b"DIDUpdate",
                    b"1.0.0",
                    key_id[: key_id.find("#")].encode("utf-8"),
                    b"af01",
                ],
                chain_id,
            )
            is False
        )

    def test_invalid_entry(self):
        chain_id = secrets.token_hex(32)
        did = "{}:{}".format(DID_METHOD_NAME, chain_id)

        # Entry with invalid property names
        with pytest.raises(ValidationError):
            self.VALIDATOR.validate(
                {
                    "added": {
                        "managementKey": [
                            ManagementKey(
                                alias="my-man-key-1",
                                controller=did,
                                key_type=KeyType.EdDSA,
                                priority=0,
                            ).to_entry_dict(did)
                        ]
                    }
                }
            )

        # Entry with invalid property names
        with pytest.raises(ValidationError):
            self.VALIDATOR.validate(
                {
                    "add": {
                        "managementKey": [
                            ManagementKey(
                                alias="my-man-key-1",
                                controller=did,
                                key_type=KeyType.EdDSA,
                                priority=0,
                            ).to_entry_dict(did)
                        ]
                    },
                    "remove": {"managementKey": [{"id": "management-1"}]},
                }
            )

        # Entry with additional properties
        with pytest.raises(ValidationError):
            self.VALIDATOR.validate(
                {
                    "add": {
                        "managementKey": [
                            ManagementKey(
                                alias="my-man-key-1",
                                controller=did,
                                key_type=KeyType.EdDSA,
                                priority=0,
                            ).to_entry_dict(did)
                        ]
                    },
                    "revoke": {"managementKey": [{"id": "management-1"}]},
                    "additional": {},
                }
            )

    def test_valid_entry(self):
        chain_id = secrets.token_hex(32)
        did = "{}:{}".format(DID_METHOD_NAME, chain_id)
        key_id = "{}#{}".format(did, "my-man-key-1")

        validate_did_update_ext_ids_v100(
            [b"DIDUpdate", b"1.0.0", key_id.encode("utf-8"), b"affe"], chain_id
        )

        # Entry with only additions should be valid
        self.VALIDATOR.validate(
            {
                "add": {
                    "managementKey": [
                        ManagementKey(
                            alias="my-man-key-1",
                            controller=did,
                            key_type=KeyType.EdDSA,
                            priority=0,
                        ).to_entry_dict(did),
                        ManagementKey(
                            alias="my-man-key-2",
                            controller=did,
                            key_type=KeyType.RSA,
                            priority=1,
                        ).to_entry_dict(did),
                    ],
                    "didKey": [
                        DIDKey(
                            alias="my-did-key",
                            controller=did,
                            key_type=KeyType.RSA.ECDSA,
                            purpose=DIDKeyPurpose.PublicKey,
                        ).to_entry_dict(did)
                    ],
                }
            }
        )

        # Entry with only revocations should be valid
        self.VALIDATOR.validate(
            {
                "revoke": {
                    "managementKey": [{"id": "management-key-1"}],
                    "didKey": [
                        {"id": "did-key-1"},
                        {"id": "did-key-2", "purpose": ["authentication"]},
                    ],
                    "service": [{"id": "service-1"}],
                }
            }
        )

        # Entry with both additions and revocations should be valid
        self.VALIDATOR.validate(
            {
                "add": {
                    "managementKey": [
                        ManagementKey(
                            alias="my-man-key-1",
                            controller=did,
                            key_type=KeyType.EdDSA,
                            priority=0,
                        ).to_entry_dict(did),
                        ManagementKey(
                            alias="my-man-key-2",
                            controller=did,
                            key_type=KeyType.RSA,
                            priority=1,
                        ).to_entry_dict(did),
                    ],
                    "didKey": [
                        DIDKey(
                            alias="my-did-key",
                            controller=did,
                            key_type=KeyType.RSA.ECDSA,
                            purpose=DIDKeyPurpose.PublicKey,
                        ).to_entry_dict(did)
                    ],
                    "service": [
                        Service(
                            alias="gmail-service",
                            service_type="email-service",
                            endpoint="https://gmail.com",
                        ).to_entry_dict(did)
                    ],
                },
                "revoke": {
                    "managementKey": [{"id": "management-key-1"}],
                    "didKey": [
                        {"id": "did-key-1"},
                        {"id": "did-key-2", "purpose": ["publicKey"]},
                    ],
                    "service": [{"id": "service-1"}],
                },
            }
        )


class TestDIDMethodVersionUpgradeEntryValidation:
    VALIDATOR = get_schema_validator("did_method_version_upgrade_entry.json")

    def test_insufficient_extids(self):
        chain_id = secrets.token_hex(32)
        assert (
            validate_did_method_version_upgrade_ext_ids_v100(
                [
                    b"DIDMethodVersionUpgrade",
                    b"1.0.0",
                    "{}:{}#my-key".format(DID_METHOD_NAME, chain_id).encode("utf-8"),
                ],
                chain_id,
            )
            is False
        )

    def test_malformed_extids(self):
        chain_id = secrets.token_hex(32)
        key_id = "{}:{}#{}".format(DID_METHOD_NAME, chain_id, "my-man-key-1")
        assert (
            validate_did_method_version_upgrade_ext_ids_v100(
                [
                    b"DIDMethodVersionsUpgrade",
                    b"1.0.0",
                    key_id.encode("utf-8"),
                    b"af01",
                ],
                chain_id,
            )
            is False
        )

        assert (
            validate_did_method_version_upgrade_ext_ids_v100(
                [b"DIDMethodVersionUpgrade", b"1.0.", key_id.encode("utf-8"), b"af01"],
                chain_id,
            )
            is False
        )

        assert (
            validate_did_method_version_upgrade_ext_ids_v100(
                [
                    b"DIDMethodVersionUpgrade",
                    b"1.0.0",
                    key_id[: key_id.find("#")].encode("utf-8"),
                    b"0xaf01",
                ],
                chain_id,
            )
            is False
        )

    def test_invalid_entry(self):
        # Empty Entry
        with pytest.raises(ValidationError):
            self.VALIDATOR.validate({})

        # Entry with an invalid property name
        with pytest.raises(ValidationError):
            self.VALIDATOR.validate({"didMethodVersions": "1.0.2"})

        # Entry with an invalid property value
        with pytest.raises(ValidationError):
            self.VALIDATOR.validate({"didMethodVersion": "1.0.2a"})

        # Entry with additional properties
        with pytest.raises(ValidationError):
            self.VALIDATOR.validate({"didMethodVersion": "1.0.2", "additional": 1})

    def test_valid_entry(self):
        chain_id = secrets.token_hex(32)
        key_id = "{}:{}#{}".format(DID_METHOD_NAME, chain_id, "my-man-key-1")
        assert (
            validate_did_method_version_upgrade_ext_ids_v100(
                [b"DIDMethodVersionUpgrade", b"1.0.0", key_id.encode("utf-8"), b"af01"],
                chain_id,
            )
            is True
        )
        self.VALIDATOR.validate({"didMethodVersion": "1.0.2"})


class TestDIDDeactivationEntryValidation:
    def test_insufficient_extids(self):
        chain_id = secrets.token_hex(32)
        assert (
            validate_did_deactivation_ext_ids_v100(
                [
                    b"DIDDeactivation",
                    b"1.0.0",
                    "{}:{}#my-key".format(DID_METHOD_NAME, chain_id).encode("utf-8"),
                ],
                chain_id,
            )
            is False
        )

    def test_malformed_extids(self):
        chain_id = secrets.token_hex(32)
        key_id = "{}:{}#{}".format(DID_METHOD_NAME, chain_id, "my-man-key-1")
        assert (
            validate_did_deactivation_ext_ids_v100(
                [b"DIDDeactivated", b"1.0.0", key_id.encode("utf-8"), b"af01"], chain_id
            )
            is False
        )

        assert (
            validate_did_deactivation_ext_ids_v100(
                [b"DIDDeactivation", b"1.0.", key_id.encode("utf-8"), b"af01"], chain_id
            )
            is False
        )

        assert (
            validate_did_deactivation_ext_ids_v100(
                [
                    b"DIDDeactivation",
                    b"1.0.0",
                    key_id[: key_id.find("#")].encode("utf-8"),
                    b"af01",
                ],
                chain_id,
            )
            is False
        )

    def test_invalid_entry(self):
        with pytest.raises(ValidationError):
            EmptyEntryContentValidator.validate({"some": "data"})

    def test_valid_entry(self):
        chain_id = secrets.token_hex(32)
        key_id = "{}:{}#{}".format(DID_METHOD_NAME, chain_id, "my-man-key-1")
        assert (
            validate_did_deactivation_ext_ids_v100(
                [b"DIDDeactivation", b"1.0.0", key_id.encode("utf-8"), b"af01"],
                chain_id,
            )
            is True
        )
        EmptyEntryContentValidator.validate({})
