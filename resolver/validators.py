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

    _validate_ext_ids_length(ext_ids, 2, EntryType.Create, MalformedDIDManagementEntry)
    _validate_entry_type(ext_ids, EntryType.Create, MalformedDIDManagementEntry)
    _validate_schema_version(ext_ids, EntryType.Create, MalformedDIDManagementEntry)
    _validate_entry_content(
        content, EntryType.Create, schema_validator, MalformedDIDManagementEntry
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
    _validate_ext_ids_length(ext_ids, 4, EntryType.Update, MalformedDIDUpdateEntry)
    _validate_entry_type(ext_ids, EntryType.Update, MalformedDIDUpdateEntry)
    _validate_schema_version(ext_ids, EntryType.Update, MalformedDIDUpdateEntry)
    _validate_key_identifier(ext_ids, EntryType.Update, MalformedDIDUpdateEntry)
    _validate_signature_format(ext_ids, EntryType.Update, MalformedDIDUpdateEntry)
    _validate_entry_content(
        content, EntryType.Update, schema_validator, MalformedDIDUpdateEntry
    )


def validate_did_method_version_upgrade_entry_format(
    ext_ids, content, schema_validator
):
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
    _validate_ext_ids_length(
        ext_ids, 4, EntryType.VersionUpgrade, MalformedDIDMethodVersionUpgradeEntry
    )
    _validate_entry_type(
        ext_ids, EntryType.VersionUpgrade, MalformedDIDMethodVersionUpgradeEntry
    )
    _validate_schema_version(
        ext_ids, EntryType.VersionUpgrade, MalformedDIDMethodVersionUpgradeEntry
    )
    _validate_key_identifier(
        ext_ids, EntryType.VersionUpgrade, MalformedDIDMethodVersionUpgradeEntry
    )
    _validate_signature_format(
        ext_ids, EntryType.VersionUpgrade, MalformedDIDMethodVersionUpgradeEntry
    )
    _validate_entry_content(
        content,
        EntryType.VersionUpgrade,
        schema_validator,
        MalformedDIDMethodVersionUpgradeEntry,
    )


def validate_did_deactivation_entry_format(ext_ids, content):
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
    _validate_ext_ids_length(
        ext_ids, 4, EntryType.Deactivation, MalformedDIDDeactivationEntry
    )
    _validate_entry_type(ext_ids, EntryType.Deactivation, MalformedDIDDeactivationEntry)
    _validate_schema_version(
        ext_ids, EntryType.Deactivation, MalformedDIDDeactivationEntry
    )
    _validate_key_identifier(
        ext_ids, EntryType.Deactivation, MalformedDIDDeactivationEntry
    )
    _validate_signature_format(
        ext_ids, EntryType.Deactivation, MalformedDIDDeactivationEntry
    )

    # The content of a DIDDeactivation entry must be empty
    if content:
        raise MalformedDIDDeactivationEntry(
            "Malformed {} entry content".format(EntryType.Deactivation.value)
        )


def _validate_ext_ids_length(ext_ids, min_length, entry_type, exception):
    if len(ext_ids) < min_length:
        raise exception(
            "{} entry must have at least {} ExtIDs".format(entry_type.value, min_length)
        )


def _validate_entry_type(ext_ids, entry_type, exception):
    if ext_ids[0] != entry_type.value:
        raise exception(
            "First ExtID of {} entry must be {}".format(
                entry_type.value, entry_type.value
            )
        )


def _validate_schema_version(ext_ids, entry_type, exception):
    if re.match(r"^\d+\.\d+\.\d+$", ext_ids[1]) is None:
        raise exception(
            "Second ExtID of {} entry must be a semantic version number".format(
                entry_type.value
            )
        )


def _validate_key_identifier(ext_ids, entry_type, exception):
    if (
        re.match(
            r"^{}:[0-9a-f]{{64}}#[a-zA-Z0-9-]+$".format(DID_METHOD_NAME), ext_ids[2]
        )
        is None
    ):
        raise exception(
            "Third ExtID of {} entry must be a valid full key identifier".format(
                entry_type.value
            )
        )


def _validate_signature_format(ext_ids, entry_type, exception):
    if re.match(r"^0x[0-9a-f]+$", ext_ids[3]) is None:
        raise exception(
            "Fourth ExtID of {} entry must be a hex string with leading 0x".format(
                entry_type.value
            )
        )


def _validate_entry_content(content, entry_type, schema_validator, exception):
    try:
        schema_validator.validate(content)
    except ValidationError:
        raise exception("Malformed {} entry content".format(entry_type.value))
