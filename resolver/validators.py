import re

from client.enums import EntryType
from resolver.exceptions import MalformedDIDManagementEntry

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
