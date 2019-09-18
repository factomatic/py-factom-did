import json
from os.path import abspath, dirname, join
import secrets

import pytest
import jsonref
from jsonschema.validators import validator_for

from client.constants import DID_METHOD_NAME
from client.enums import DIDKeyPurpose, SignatureType
from client.keys import DIDKey, ManagementKey
from client.service import Service
from resolver.exceptions import (
    MalformedDIDDeactivationEntry,
    MalformedDIDManagementEntry,
    MalformedDIDMethodVersionUpgradeEntry,
    MalformedDIDUpdateEntry,
)
from resolver.validators import (
    validate_did_deactivation_entry_format,
    validate_did_management_entry_format,
    validate_did_update_entry_format,
    validate_did_method_version_upgrade_entry_format,
)


def load_json_schema(filename, version="1.0.0"):
    """Loads the given schema file"""

    relative_path = join("./resolver/schemas", version, filename)
    absolute_path = abspath(relative_path)

    base_path = dirname(absolute_path)
    base_uri = "file://{}/".format(base_path)

    with open(absolute_path) as schema_file:
        return jsonref.loads(schema_file.read(), base_uri=base_uri, jsonschema=True)


def get_validator(schema):
    cls = validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)


class TestDIDManagementEntryValidation:
    VALIDATOR = get_validator(load_json_schema("did_management_entry.json"))

    def test_insufficient_extids(self):
        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_entry_format(["DIDManagement"], {}, self.VALIDATOR)
        assert str(excinfo.value) == "DIDManagement entry must have at least two ExtIDs"

    def test_malformed_extids(self):
        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_entry_format(
                ["DIdManagement", "1.0.0"], {}, self.VALIDATOR
            )
        assert (
            str(excinfo.value)
            == "First ExtID of DIDManagement entry must be DIDManagement"
        )

        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_entry_format(
                ["DIDManagement", "1.0.a"], {}, self.VALIDATOR
            )
        assert (
            str(excinfo.value)
            == "Second ExtID of DIDManagement entry must be a semantic version number"
        )

    def test_entry_with_missing_required_fields(self):
        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_entry_format(
                ["DIDManagement", "1.0.0"], {}, self.VALIDATOR
            )
        assert str(excinfo.value) == "Malformed DIDManagement entry content"

        missing_management_keys = json.dumps({"didMethodVersion": "0.2.0"})
        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_entry_format(
                ["DIDManagement", "1.0.0"], missing_management_keys, self.VALIDATOR
            )
        assert str(excinfo.value) == "Malformed DIDManagement entry content"

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
        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_entry_format(
                ["DIDManagement", "1.0.0"], missing_did_method_version, self.VALIDATOR
            )
        assert str(excinfo.value) == "Malformed DIDManagement entry content"

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
        validate_did_management_entry_format(
            ["DIDManagement", "1.0.0"], valid_entry, self.VALIDATOR
        )


class TestDIDUpdateEntryValidation:
    VALIDATOR = get_validator(load_json_schema("did_update_entry.json"))

    def test_insufficient_extids(self):
        with pytest.raises(MalformedDIDUpdateEntry) as excinfo:
            validate_did_update_entry_format(
                [
                    "DIDUpdate",
                    "1.0.0",
                    "{}:{}#my-key".format(DID_METHOD_NAME, secrets.token_hex(32)),
                ],
                {},
                self.VALIDATOR,
            )
        assert str(excinfo.value) == "DIDUpdate entry must have at least four ExtIDs"

    def test_malformed_extids(self):
        key_id = "{}:{}#{}".format(
            DID_METHOD_NAME, secrets.token_hex(32), "my-man-key-1"
        )
        with pytest.raises(MalformedDIDUpdateEntry) as excinfo:
            validate_did_update_entry_format(
                ["DIdUpdate", "1.0.0", key_id, "0xaf01"], {}, self.VALIDATOR
            )
        assert str(excinfo.value) == "First ExtID of DIDUpdate entry must be DIDUpdate"

        with pytest.raises(MalformedDIDUpdateEntry) as excinfo:
            validate_did_update_entry_format(
                ["DIDUpdate", "1.0.", key_id, "0xaf01"], {}, self.VALIDATOR
            )
        assert (
            str(excinfo.value)
            == "Second ExtID of DIDUpdate entry must be a semantic version number"
        )

        with pytest.raises(MalformedDIDUpdateEntry) as excinfo:
            validate_did_update_entry_format(
                ["DIDUpdate", "1.0.0", key_id[: key_id.find("#")], "0xaf01"],
                {},
                self.VALIDATOR,
            )
        assert (
            str(excinfo.value)
            == "Third ExtID of DIDUpdate entry must be a valid full key identifier"
        )

        with pytest.raises(MalformedDIDUpdateEntry) as excinfo:
            validate_did_update_entry_format(
                ["DIDUpdate", "1.0.0", key_id, "aff0"], {}, self.VALIDATOR
            )
        assert (
            str(excinfo.value)
            == "Fourth ExtID of DIDUpdate entry must be a hex string with leading 0x"
        )

        with pytest.raises(MalformedDIDUpdateEntry) as excinfo:
            validate_did_update_entry_format(
                ["DIDUpdate", "1.0.0", key_id, "0xaffz"], {}, self.VALIDATOR
            )
        assert (
            str(excinfo.value)
            == "Fourth ExtID of DIDUpdate entry must be a hex string with leading 0x"
        )

    def test_invalid_entry(self):
        did = "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))
        key_id = "{}#{}".format(did, "my-man-key-1")

        # Entry with invalid property names
        with pytest.raises(MalformedDIDUpdateEntry) as excinfo:
            validate_did_update_entry_format(
                ["DIDUpdate", "1.0.0", key_id, "0xaffe"],
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
                },
                self.VALIDATOR,
            )
        assert str(excinfo.value) == "Malformed DIDUpdate entry content"

        # Entry with invalid property names
        with pytest.raises(MalformedDIDUpdateEntry) as excinfo:
            validate_did_update_entry_format(
                ["DIDUpdate", "1.0.0", key_id, "0xaffe"],
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
                },
                self.VALIDATOR,
            )
        assert str(excinfo.value) == "Malformed DIDUpdate entry content"

        # Entry with additional properties
        with pytest.raises(MalformedDIDUpdateEntry) as excinfo:
            validate_did_update_entry_format(
                ["DIDUpdate", "1.0.0", key_id, "0xaffe"],
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
                },
                self.VALIDATOR,
            )
        assert str(excinfo.value) == "Malformed DIDUpdate entry content"

    def test_valid_entry(self):
        did = "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))
        key_id = "{}#{}".format(did, "my-man-key-1")

        # Empty entry content should be valid
        validate_did_update_entry_format(
            ["DIDUpdate", "1.0.0", key_id, "0xaffe"], {}, self.VALIDATOR
        )

        # Entry with only additions should be valid
        validate_did_update_entry_format(
            ["DIDUpdate", "1.0.0", key_id, "0xaffe"],
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
            },
            self.VALIDATOR,
        )

        # Entry with only revocations should be valid
        validate_did_update_entry_format(
            ["DIDUpdate", "1.0.0", key_id, "0xaffe"],
            {
                "revoke": {
                    "managementKey": [{"id": "management-key-1"}],
                    "didKey": [
                        {"id": "did-key-1"},
                        {"id": "did-key-2", "purpose": ["authentication"]},
                    ],
                    "service": [{"id": "service-1"}],
                }
            },
            self.VALIDATOR,
        )

        # Entry with both additions and revocations should be valid
        validate_did_update_entry_format(
            ["DIDUpdate", "1.0.0", key_id, "0xaffe"],
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
            },
            self.VALIDATOR,
        )


class TestDIDMethodVersionUpgradeEntryValidation:
    VALIDATOR = get_validator(load_json_schema("did_method_version_upgrade_entry.json"))

    def test_insufficient_extids(self):
        with pytest.raises(MalformedDIDMethodVersionUpgradeEntry) as excinfo:
            validate_did_method_version_upgrade_entry_format(
                [
                    "DIDMethodVersionUpgrade",
                    "1.0.0",
                    "{}:{}#my-key".format(DID_METHOD_NAME, secrets.token_hex(32)),
                ],
                {},
                self.VALIDATOR,
            )
        assert (
            str(excinfo.value)
            == "DIDMethodVersionUpgrade entry must have at least four ExtIDs"
        )

    def test_malformed_extids(self):
        key_id = "{}:{}#{}".format(
            DID_METHOD_NAME, secrets.token_hex(32), "my-man-key-1"
        )
        with pytest.raises(MalformedDIDMethodVersionUpgradeEntry) as excinfo:
            validate_did_method_version_upgrade_entry_format(
                ["DIDMethodVersionsUpgrade", "1.0.0", key_id, "0xaf01"],
                {},
                self.VALIDATOR,
            )
        assert (
            str(excinfo.value)
            == "First ExtID of DIDMethodVersionUpgrade entry must be DIDMethodVersionUpgrade"
        )

        with pytest.raises(MalformedDIDMethodVersionUpgradeEntry) as excinfo:
            validate_did_method_version_upgrade_entry_format(
                ["DIDMethodVersionUpgrade", "1.0.", key_id, "0xaf01"],
                {},
                self.VALIDATOR,
            )
        assert (
            str(excinfo.value)
            == "Second ExtID of DIDMethodVersionUpgrade entry must be a semantic version number"
        )

        with pytest.raises(MalformedDIDMethodVersionUpgradeEntry) as excinfo:
            validate_did_method_version_upgrade_entry_format(
                [
                    "DIDMethodVersionUpgrade",
                    "1.0.0",
                    key_id[: key_id.find("#")],
                    "0xaf01",
                ],
                {},
                self.VALIDATOR,
            )
        assert (
            str(excinfo.value)
            == "Third ExtID of DIDMethodVersionUpgrade entry must be a valid full key identifier"
        )

        with pytest.raises(MalformedDIDMethodVersionUpgradeEntry) as excinfo:
            validate_did_method_version_upgrade_entry_format(
                ["DIDMethodVersionUpgrade", "1.0.0", key_id, "aff0"], {}, self.VALIDATOR
            )
        assert (
            str(excinfo.value)
            == "Fourth ExtID of DIDMethodVersionUpgrade entry must be a hex string with leading 0x"
        )

        with pytest.raises(MalformedDIDMethodVersionUpgradeEntry) as excinfo:
            validate_did_method_version_upgrade_entry_format(
                ["DIDMethodVersionUpgrade", "1.0.0", key_id, "0xaffz"],
                {},
                self.VALIDATOR,
            )
        assert (
            str(excinfo.value)
            == "Fourth ExtID of DIDMethodVersionUpgrade entry must be a hex string with leading 0x"
        )

    def test_invalid_entry(self):
        did = "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))
        key_id = "{}#{}".format(did, "my-man-key-1")

        # Empty Entry
        with pytest.raises(MalformedDIDMethodVersionUpgradeEntry) as excinfo:
            validate_did_method_version_upgrade_entry_format(
                ["DIDMethodVersionUpgrade", "1.0.0", key_id, "0xaf014"],
                {},
                self.VALIDATOR,
            )
        assert str(excinfo.value) == "Malformed DIDMethodVersionUpgrade entry content"

        # Entry with an invalid property name
        with pytest.raises(MalformedDIDMethodVersionUpgradeEntry) as excinfo:
            validate_did_method_version_upgrade_entry_format(
                ["DIDMethodVersionUpgrade", "1.0.0", key_id, "0xaf014"],
                {"didMethodVersions": "1.0.2"},
                self.VALIDATOR,
            )
        assert str(excinfo.value) == "Malformed DIDMethodVersionUpgrade entry content"

        # Entry with an invalid property value
        with pytest.raises(MalformedDIDMethodVersionUpgradeEntry) as excinfo:
            validate_did_method_version_upgrade_entry_format(
                ["DIDMethodVersionUpgrade", "1.0.0", key_id, "0xaf014"],
                {"didMethodVersion": "1.0.2a"},
                self.VALIDATOR,
            )
        assert str(excinfo.value) == "Malformed DIDMethodVersionUpgrade entry content"

        # Entry with additional properties
        with pytest.raises(MalformedDIDMethodVersionUpgradeEntry) as excinfo:
            validate_did_method_version_upgrade_entry_format(
                ["DIDMethodVersionUpgrade", "1.0.0", key_id, "0xaf014"],
                {"didMethodVersion": "1.0.2", "additional": 1},
                self.VALIDATOR,
            )
        assert str(excinfo.value) == "Malformed DIDMethodVersionUpgrade entry content"

    def test_valid_entry(self):
        did = "{}:{}".format(DID_METHOD_NAME, secrets.token_hex(32))
        key_id = "{}#{}".format(did, "my-man-key-1")

        validate_did_method_version_upgrade_entry_format(
            ["DIDMethodVersionUpgrade", "1.0.0", key_id, "0xaf014"],
            {"didMethodVersion": "1.0.2"},
            self.VALIDATOR,
        )


class TestDIDDeactivationEntryValidation:
    def test_insufficient_extids(self):
        with pytest.raises(MalformedDIDDeactivationEntry) as excinfo:
            validate_did_deactivation_entry_format(
                [
                    "DIDDeactivation",
                    "1.0.0",
                    "{}:{}#my-key".format(DID_METHOD_NAME, secrets.token_hex(32)),
                ],
                {},
            )
        assert (
            str(excinfo.value) == "DIDDeactivation entry must have at least four ExtIDs"
        )

    def test_malformed_extids(self):
        key_id = "{}:{}#{}".format(
            DID_METHOD_NAME, secrets.token_hex(32), "my-man-key-1"
        )
        with pytest.raises(MalformedDIDDeactivationEntry) as excinfo:
            validate_did_deactivation_entry_format(
                ["DIDDeactivated", "1.0.0", key_id, "0xaf01"], {}
            )
        assert (
            str(excinfo.value)
            == "First ExtID of DIDDeactivation entry must be DIDDeactivation"
        )

        with pytest.raises(MalformedDIDDeactivationEntry) as excinfo:
            validate_did_deactivation_entry_format(
                ["DIDDeactivation", "1.0.", key_id, "0xaf01"], {}
            )
        assert (
            str(excinfo.value)
            == "Second ExtID of DIDDeactivation entry must be a semantic version number"
        )

        with pytest.raises(MalformedDIDDeactivationEntry) as excinfo:
            validate_did_deactivation_entry_format(
                ["DIDDeactivation", "1.0.0", key_id[: key_id.find("#")], "0xaf01"], {}
            )
        assert (
            str(excinfo.value)
            == "Third ExtID of DIDDeactivation entry must be a valid full key identifier"
        )

        with pytest.raises(MalformedDIDDeactivationEntry) as excinfo:
            validate_did_deactivation_entry_format(
                ["DIDDeactivation", "1.0.0", key_id, "aff0"], {}
            )
        assert (
            str(excinfo.value)
            == "Fourth ExtID of DIDDeactivation entry must be a hex string with leading 0x"
        )

        with pytest.raises(MalformedDIDDeactivationEntry) as excinfo:
            validate_did_deactivation_entry_format(
                ["DIDDeactivation", "1.0.0", key_id, "0xaffz"], {}
            )
        assert (
            str(excinfo.value)
            == "Fourth ExtID of DIDDeactivation entry must be a hex string with leading 0x"
        )

    def test_invalid_entry(self):
        key_id = "{}:{}#{}".format(
            DID_METHOD_NAME, secrets.token_hex(32), "my-man-key-1"
        )
        with pytest.raises(MalformedDIDDeactivationEntry) as excinfo:
            validate_did_deactivation_entry_format(
                ["DIDDeactivation", "1.0.0", key_id, "0xaff0"], {"some": "data"}
            )
        assert str(excinfo.value) == "Malformed DIDDeactivation entry content"

    def test_valid_entry(self):
        key_id = "{}:{}#{}".format(
            DID_METHOD_NAME, secrets.token_hex(32), "my-man-key-1"
        )
        validate_did_deactivation_entry_format(
            ["DIDDeactivation", "1.0.0", key_id, "0xaff0"], {}
        )
