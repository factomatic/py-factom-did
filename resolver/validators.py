import re

from client.constants import DID_METHOD_NAME
from client.enums import EntryType
from resolver.exceptions import MalformedDIDManagementEntry, MalformedDIDUpdateEntry

from jsonschema.exceptions import ValidationError


def validate_did_management_entry_format(ext_ids, content, schema_validator):
    if len(ext_ids) < 2:
        raise MalformedDIDManagementEntry(
            "DIDManagement entry must have at least two ExtIDs"
        )
    if ext_ids[0] != EntryType.Create.value:
        raise MalformedDIDManagementEntry(
            "First ExtID of DIDManagement entry must be {}".format(
                EntryType.Create.value
            )
        )
    if re.match(r"^\d+\.\d+\.\d+$", ext_ids[1]) is None:
        raise MalformedDIDManagementEntry(
            "Second ExtID of DIDManagement entry must be a semantic version number"
        )

    try:
        schema_validator.validate(content)
    except ValidationError:
        raise MalformedDIDManagementEntry("Malformed DIDManagement entry content")


def validate_did_update_entry_format(ext_ids, content, schema_validator):
    if len(ext_ids) < 4:
        raise MalformedDIDUpdateEntry("DIDUpdate entry must have at least four ExtIDs")
    if ext_ids[0] != EntryType.Update.value:
        raise MalformedDIDUpdateEntry(
            "First ExtID of DIDUpdate entry must be {}".format(EntryType.Update.value)
        )
    if re.match(r"^\d+\.\d+\.\d+$", ext_ids[1]) is None:
        raise MalformedDIDUpdateEntry(
            "Second ExtID of DIDUpdate entry must be a semantic version number"
        )
    if (
        re.match(
            r"^{}:[0-9a-f]{{64}}#[a-zA-Z0-9-]+$".format(DID_METHOD_NAME), ext_ids[2]
        )
        is None
    ):
        raise MalformedDIDUpdateEntry(
            "Third ExtID of DIDUpdate entry must be a valid full key identifier"
        )
    if re.match(r"^0x[0-9a-f]+$", ext_ids[3]) is None:
        raise MalformedDIDUpdateEntry(
            "Fourth ExtID of DIDUpdate entry must be a hex string with leading 0x"
        )

    try:
        schema_validator.validate(content)
    except ValidationError:
        raise MalformedDIDUpdateEntry("Malformed DIDUpdate entry content")
