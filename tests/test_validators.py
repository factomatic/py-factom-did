import json
import secrets

from jsonschema.exceptions import ValidationError
import pytest

from client.constants import DID_METHOD_NAME
from client.enums import DIDKeyPurpose, SignatureType
from client.keys import DIDKey, ManagementKey
from client.service import Service
from resolver.exceptions import MalformedDIDManagementEntry
from resolver.schema import get_schema_validator
from resolver.validators import (
    validate_did_deactivation_ext_ids_v100,
    validate_did_management_ext_ids_v100,
    validate_did_method_version_upgrade_ext_ids_v100,
    validate_did_update_ext_ids_v100,
    DeactivationEntryContentValidator,
)


class TestDIDManagementEntryValidation:
    VALIDATOR = get_schema_validator("did_management_entry.json")

    def test_insufficient_extids(self):
        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_ext_ids_v100(["DIDManagement"])
        assert str(excinfo.value) == "Invalid or missing DIDManagement entry ExtIDs"

    def test_malformed_extids(self):
        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_ext_ids_v100(["DIdManagement", "1.0.0"])
        assert str(excinfo.value) == "Invalid or missing DIDManagement entry ExtIDs"

        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_ext_ids_v100(["DIDManagement", "1.0.a"])
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
                    signature_type=SignatureType.EdDSA.value,
                    priority="0",
                ).to_entry_dict(did)
            ]
        }
        with pytest.raises(ValidationError):
            self.VALIDATOR.validate(missing_did_method_version)

    def test_valid_entry(self):
        did = "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))
        valid_entry = {
            "didMethodVersion": "0.1.0",
            "managementKey": [
                ManagementKey(
                    alias="my-man-key-1",
                    controller=did,
                    signature_type=SignatureType.EdDSA.value,
                    priority="0",
                ).to_entry_dict(did),
                ManagementKey(
                    alias="my-man-key-2",
                    controller=did,
                    signature_type=SignatureType.RSA.value,
                    priority="1",
                ).to_entry_dict(did),
            ],
            "didKey": [
                DIDKey(
                    alias="my-did-key",
                    controller=did,
                    signature_type=SignatureType.RSA.ECDSA.value,
                    purpose=DIDKeyPurpose.PublicKey.value,
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
        assert (
            validate_did_update_ext_ids_v100(
                [
                    "DIDUpdate",
                    "1.0.0",
                    "{}:{}#my-key".format(DID_METHOD_NAME, secrets.token_hex(32)),
                ]
            )
            is False
        )

    def test_malformed_extids(self):
        key_id = "{}:{}#{}".format(
            DID_METHOD_NAME, secrets.token_hex(32), "my-man-key-1"
        )
        assert (
            validate_did_update_ext_ids_v100(["DIdUpdate", "1.0.0", key_id, "0xaf01"])
            is False
        )

        assert (
            validate_did_update_ext_ids_v100(["DIDUpdate", "1.0.", key_id, "0xaf01"])
            is False
        )

        assert (
            validate_did_update_ext_ids_v100(
                ["DIDUpdate", "1.0.0", key_id[: key_id.find("#")], "0xaf01"]
            )
            is False
        )

        assert (
            validate_did_update_ext_ids_v100(["DIDUpdate", "1.0.0", key_id, "aff0"])
            is False
        )

        assert (
            validate_did_update_ext_ids_v100(["DIDUpdate", "1.0.0", key_id, "0xaffz"])
            is False
        )

    def test_invalid_entry(self):
        did = "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))

        # Entry with invalid property names
        with pytest.raises(ValidationError):
            self.VALIDATOR.validate(
                {
                    "added": {
                        "managementKey": [
                            ManagementKey(
                                alias="my-man-key-1",
                                controller=did,
                                signature_type=SignatureType.EdDSA.value,
                                priority="0",
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
                                signature_type=SignatureType.EdDSA.value,
                                priority="0",
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
                                signature_type=SignatureType.EdDSA.value,
                                priority="0",
                            ).to_entry_dict(did)
                        ]
                    },
                    "revoke": {"managementKey": [{"id": "management-1"}]},
                    "additional": {},
                }
            )

    def test_valid_entry(self):
        did = "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))
        key_id = "{}#{}".format(did, "my-man-key-1")

        # Empty entry content should be valid
        validate_did_update_ext_ids_v100(["DIDUpdate", "1.0.0", key_id, "0xaffe"])

        # Entry with only additions should be valid
        self.VALIDATOR.validate(
            {
                "add": {
                    "managementKey": [
                        ManagementKey(
                            alias="my-man-key-1",
                            controller=did,
                            signature_type=SignatureType.EdDSA.value,
                            priority="0",
                        ).to_entry_dict(did),
                        ManagementKey(
                            alias="my-man-key-2",
                            controller=did,
                            signature_type=SignatureType.RSA.value,
                            priority="1",
                        ).to_entry_dict(did),
                    ],
                    "didKey": [
                        DIDKey(
                            alias="my-did-key",
                            controller=did,
                            signature_type=SignatureType.RSA.ECDSA.value,
                            purpose=DIDKeyPurpose.PublicKey.value,
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
                            signature_type=SignatureType.EdDSA.value,
                            priority="0",
                        ).to_entry_dict(did),
                        ManagementKey(
                            alias="my-man-key-2",
                            controller=did,
                            signature_type=SignatureType.RSA.value,
                            priority="1",
                        ).to_entry_dict(did),
                    ],
                    "didKey": [
                        DIDKey(
                            alias="my-did-key",
                            controller=did,
                            signature_type=SignatureType.RSA.ECDSA.value,
                            purpose=DIDKeyPurpose.PublicKey.value,
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
        assert (
            validate_did_method_version_upgrade_ext_ids_v100(
                [
                    "DIDMethodVersionUpgrade",
                    "1.0.0",
                    "{}:{}#my-key".format(DID_METHOD_NAME, secrets.token_hex(32)),
                ]
            )
            is False
        )

    def test_malformed_extids(self):
        key_id = "{}:{}#{}".format(
            DID_METHOD_NAME, secrets.token_hex(32), "my-man-key-1"
        )
        assert (
            validate_did_method_version_upgrade_ext_ids_v100(
                ["DIDMethodVersionsUpgrade", "1.0.0", key_id, "0xaf01"]
            )
            is False
        )

        assert (
            validate_did_method_version_upgrade_ext_ids_v100(
                ["DIDMethodVersionUpgrade", "1.0.", key_id, "0xaf01"]
            )
            is False
        )

        assert (
            validate_did_method_version_upgrade_ext_ids_v100(
                [
                    "DIDMethodVersionUpgrade",
                    "1.0.0",
                    key_id[: key_id.find("#")],
                    "0xaf01",
                ]
            )
            is False
        )

        assert (
            validate_did_method_version_upgrade_ext_ids_v100(
                ["DIDMethodVersionUpgrade", "1.0.0", key_id, "aff0"]
            )
            is False
        )

        assert (
            validate_did_method_version_upgrade_ext_ids_v100(
                ["DIDMethodVersionUpgrade", "1.0.0", key_id, "0xaffz"]
            )
            is False
        )

    def test_invalid_entry(self):
        did = "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))
        key_id = "{}#{}".format(did, "my-man-key-1")

        # Empty Entry
        with pytest.raises(ValidationError):
            self.VALIDATOR.validate({})

        # Entry with an invalid property name
        with pytest.raises(ValidationError):
            self.VALIDATOR.validate({"didMethodVersions": "1.0.2"})

        # Entry with an invalid property value
        with pytest.raises(ValidationError) as excinfo:
            self.VALIDATOR.validate({"didMethodVersion": "1.0.2a"})

        # Entry with additional properties
        with pytest.raises(ValidationError) as excinfo:
            self.VALIDATOR.validate({"didMethodVersion": "1.0.2", "additional": 1})

    def test_valid_entry(self):
        self.VALIDATOR.validate({"didMethodVersion": "1.0.2"})


class TestDIDDeactivationEntryValidation:
    def test_insufficient_extids(self):
        assert (
            validate_did_deactivation_ext_ids_v100(
                [
                    "DIDDeactivation",
                    "1.0.0",
                    "{}:{}#my-key".format(DID_METHOD_NAME, secrets.token_hex(32)),
                ]
            )
            is False
        )

    def test_malformed_extids(self):
        key_id = "{}:{}#{}".format(
            DID_METHOD_NAME, secrets.token_hex(32), "my-man-key-1"
        )
        assert (
            validate_did_deactivation_ext_ids_v100(
                ["DIDDeactivated", "1.0.0", key_id, "0xaf01"]
            )
            is False
        )

        assert (
            validate_did_deactivation_ext_ids_v100(
                ["DIDDeactivation", "1.0.", key_id, "0xaf01"]
            )
            is False
        )

        assert (
            validate_did_deactivation_ext_ids_v100(
                ["DIDDeactivation", "1.0.0", key_id[: key_id.find("#")], "0xaf01"]
            )
            is False
        )

        assert (
            validate_did_deactivation_ext_ids_v100(
                ["DIDDeactivation", "1.0.0", key_id, "aff0"]
            )
            is False
        )

        assert (
            validate_did_deactivation_ext_ids_v100(
                ["DIDDeactivation", "1.0.0", key_id, "0xaffz"]
            )
            is False
        )

    def test_invalid_entry(self):
        with pytest.raises(ValidationError):
            DeactivationEntryContentValidator.validate({"some": "data"})

    def test_valid_entry(self):
        DeactivationEntryContentValidator.validate({})
