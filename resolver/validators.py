import re

from client.constants import DID_METHOD_NAME
from client.enums import EntryType
from resolver.exceptions import (
    MalformedDIDDeactivationEntry,
    MalformedDIDManagementEntry,
    MalformedDIDMethodVersionUpgradeEntry,
    MalformedDIDUpdateEntry,
)

from jsonschema.exceptions import ValidationError


def validate_did_management_entry_format(ext_ids, content, schema_validator):
    """
    Validates the format of a DIDManagement entry.

    Parameters
    ----------
    ext_ids: list of str
        The ExtIDs of the entry
    content: dict
        The entry content
    schema_validator: jsonschema.validators.Draft7Validator
        The entry content schema validator

    Raises
    ------
    MalformedDIDManagementEntry
        If the ExtIDs or the entry content do not follow the Factom DID method specification
    """
    if len(ext_ids) < 2:
        raise MalformedDIDManagementEntry(
            "{} entry must have at least two ExtIDs".format(EntryType.Create.value)
        )
    if ext_ids[0] != EntryType.Create.value:
        raise MalformedDIDManagementEntry(
            "First ExtID of {} entry must be {}".format(
                EntryType.Create.value, EntryType.Create.value
            )
        )
    if re.match(r"^\d+\.\d+\.\d+$", ext_ids[1]) is None:
        raise MalformedDIDManagementEntry(
            "Second ExtID of {} entry must be a semantic version number".format(
                EntryType.Create.value
            )
        )

    try:
        schema_validator.validate(content)
    except ValidationError:
        raise MalformedDIDManagementEntry(
            "Malformed {} entry content".format(EntryType.Create.value)
        )


def validate_did_update_entry_format(ext_ids, content, schema_validator):
    """
    Validates the format of a DIDUpdate entry.

    Parameters
    ----------
    ext_ids: list of str
        The ExtIDs of the entry
    content: dict
        The entry content
    schema_validator: jsonschema.validators.Draft7Validator
        The entry content schema validator

    Raises
    ------
    MalformedDIDUpdateEntry
        If the ExtIDs or the entry content do not follow the Factom DID method specification
    """
    if len(ext_ids) < 4:
        raise MalformedDIDUpdateEntry(
            "{} entry must have at least four ExtIDs".format(EntryType.Update.value)
        )
    if ext_ids[0] != EntryType.Update.value:
        raise MalformedDIDUpdateEntry(
            "First ExtID of {} entry must be {}".format(
                EntryType.Update.value, EntryType.Update.value
            )
        )
    if re.match(r"^\d+\.\d+\.\d+$", ext_ids[1]) is None:
        raise MalformedDIDUpdateEntry(
            "Second ExtID of {} entry must be a semantic version number".format(
                EntryType.Update.value
            )
        )
    if (
        re.match(
            r"^{}:[0-9a-f]{{64}}#[a-zA-Z0-9-]+$".format(DID_METHOD_NAME), ext_ids[2]
        )
        is None
    ):
        raise MalformedDIDUpdateEntry(
            "Third ExtID of {} entry must be a valid full key identifier".format(
                EntryType.Update.value
            )
        )
    if re.match(r"^0x[0-9a-f]+$", ext_ids[3]) is None:
        raise MalformedDIDUpdateEntry(
            "Fourth ExtID of {} entry must be a hex string with leading 0x".format(
                EntryType.Update.value
            )
        )

    try:
        schema_validator.validate(content)
    except ValidationError:
        raise MalformedDIDUpdateEntry(
            "Malformed {} entry content".format(EntryType.Update.value)
        )


def validate_version_upgrade_entry_content(ext_ids, content, schema_validator):
    """
    Validates the format of a DIDMethodVersionUpgrade entry.

    Parameters
    ----------
    ext_ids: list of str
        The ExtIDs of the entry
    content: dict
        The entry content
    schema_validator: jsonschema.validators.Draft7Validator
        The entry content schema validator

    Raises
    ------
    MalformedDIDMethodVersionUpgradeEntry
        If the ExtIDs or the entry content do not follow the Factom DID method specification
    """
    if len(ext_ids) < 4:
        raise MalformedDIDMethodVersionUpgradeEntry(
            "{} entry must have at least four ExtIDs".format(
                EntryType.VersionUpgrade.value
            )
        )
    if ext_ids[0] != EntryType.Update.value:
        raise MalformedDIDMethodVersionUpgradeEntry(
            "First ExtID of {} entry must be {}".format(
                EntryType.VersionUpgrade.value, EntryType.VersionUpgrade.value
            )
        )
    if re.match(r"^\d+\.\d+\.\d+$", ext_ids[1]) is None:
        raise MalformedDIDMethodVersionUpgradeEntry(
            "Second ExtID of {} entry must be a semantic version number".format(
                EntryType.VersionUpgrade.value
            )
        )
    if (
        re.match(
            r"^{}:[0-9a-f]{{64}}#[a-zA-Z0-9-]+$".format(DID_METHOD_NAME), ext_ids[2]
        )
        is None
    ):
        raise MalformedDIDMethodVersionUpgradeEntry(
            "Third ExtID of {} entry must be a valid full key identifier".format(
                EntryType.VersionUpgrade.value
            )
        )
    if re.match(r"^0x[0-9a-f]+$", ext_ids[3]) is None:
        raise MalformedDIDMethodVersionUpgradeEntry(
            "Fourth ExtID of {} entry must be a hex string with leading 0x".format(
                EntryType.VersionUpgrade.value
            )
        )

    try:
        schema_validator.validate(content)
    except ValidationError:
        raise MalformedDIDMethodVersionUpgradeEntry(
            "Malformed {} entry content".format(EntryType.VersionUpgrade.value)
        )


def validate_did_deactivation_entry_content(ext_ids, content):
    """
    Validates the format of a DIDDeactivation entry.

    Parameters
    ----------
    ext_ids: list of str
        The ExtIDs of the entry
    content: dict
        The entry content

    Raises
    ------
    MalformedDIDDeactivationEntry
        If the ExtIDs or the entry content do not follow the Factom DID method specification
    """
    if len(ext_ids) < 4:
        raise MalformedDIDDeactivationEntry(
            "{} entry must have at least four ExtIDs".format(
                EntryType.Deactivation.value
            )
        )
    if ext_ids[0] != EntryType.Update.value:
        raise MalformedDIDDeactivationEntry(
            "First ExtID of {} entry must be {}".format(
                EntryType.Deactivation.value, EntryType.Deactivation.value
            )
        )
    if re.match(r"^\d+\.\d+\.\d+$", ext_ids[1]) is None:
        raise MalformedDIDDeactivationEntry(
            "Second ExtID of {} entry must be a semantic version number".format(
                EntryType.Deactivation.value
            )
        )
    if (
        re.match(
            r"^{}:[0-9a-f]{{64}}#[a-zA-Z0-9-]+$".format(DID_METHOD_NAME), ext_ids[2]
        )
        is None
    ):
        raise MalformedDIDDeactivationEntry(
            "Third ExtID of {} entry must be a valid full key identifier".format(
                EntryType.Deactivation.value
            )
        )
    if re.match(r"^0x[0-9a-f]+$", ext_ids[3]) is None:
        raise MalformedDIDDeactivationEntry(
            "Fourth ExtID of {} entry must be a hex string with leading 0x".format(
                EntryType.Deactivation.value
            )
        )

    # The content of a DIDDeactivation entry must be empty
    if content:
        raise MalformedDIDDeactivationEntry(
            "Malformed {} entry content".format(EntryType.Deactivation.value)
        )
