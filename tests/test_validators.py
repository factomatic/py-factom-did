import json
from os.path import abspath, dirname, join
import secrets

import pytest
import jsonref
from jsonschema.validators import validator_for

from client.constants import DID_METHOD_NAME
from client.enums import DIDKeyPurpose, SignatureType
from client.keys import ManagementKey, DIDKey
from client.service import Service
from resolver.exceptions import MalformedDIDManagementEntry
from resolver.validators import validate_did_management_entry_format


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
    DID_MANAGEMENT_VALIDATOR = get_validator(
        load_json_schema("did_management_entry.json")
    )

    def test_insufficient_extids(self):
        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_entry_format([], "", self.DID_MANAGEMENT_VALIDATOR)
        assert str(excinfo.value) == "DIDManagement entry must have at least two ExtIDs"

        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_entry_format(
                ["DIDManagement"], "", self.DID_MANAGEMENT_VALIDATOR
            )
        assert str(excinfo.value) == "DIDManagement entry must have at least two ExtIDs"

    def test_malformed_extids(self):
        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_entry_format(
                ["DIdManagement", "1.0.0"], "", self.DID_MANAGEMENT_VALIDATOR
            )
        assert (
            str(excinfo.value)
            == "First ExtID of DIDManagement entry must be DIDManagement"
        )

        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_entry_format(
                ["DIDManagement", "1.0.a"], "", self.DID_MANAGEMENT_VALIDATOR
            )
        assert (
            str(excinfo.value)
            == "Second ExtID of DIDManagement entry must be a semantic version number"
        )

    def test_entry_with_missing_required_fields(self):
        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_entry_format(
                ["DIDManagement", "1.0.0"], "{}", self.DID_MANAGEMENT_VALIDATOR
            )
        assert str(excinfo.value) == "Malformed DIDManagement entry content"

        missing_management_keys = json.dumps({"didMethodVersion": "0.2.0"})
        with pytest.raises(MalformedDIDManagementEntry) as excinfo:
            validate_did_management_entry_format(
                ["DIDManagement", "1.0.0"],
                missing_management_keys,
                self.DID_MANAGEMENT_VALIDATOR,
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
                ["DIDManagement", "1.0.0"],
                missing_did_method_version,
                self.DID_MANAGEMENT_VALIDATOR,
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
            ["DIDManagement", "1.0.0"], valid_entry, self.DID_MANAGEMENT_VALIDATOR
        )
