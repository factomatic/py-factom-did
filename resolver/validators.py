import re

from jsonschema.exceptions import ValidationError

from client.constants import DID_METHOD_NAME, ENTRY_SCHEMA_V100
from client.enums import EntryType
from resolver.exceptions import MalformedDIDManagementEntry


class EmptyEntryContentValidator:
    @staticmethod
    def validate(content):
        if content:
            raise ValidationError(
                "Invalid {} entry content".format(EntryType.Deactivation.value)
            )


def validate_did_management_ext_ids_v100(ext_ids):
    """
    Validates the ExtIDs of a DIDManagement entry.

    Parameters
    ----------
    ext_ids: list of bytes
        The ExtIDs of the entry

    Raises
    ------
    MalformedDIDManagementEntry
        If the ExtIDs are not valid.
    """

    if not (
        _validate_ext_ids_length(ext_ids, 2)
        and _validate_entry_type(ext_ids, EntryType.Create)
        and _validate_schema_version(ext_ids, ENTRY_SCHEMA_V100)
    ):
        raise MalformedDIDManagementEntry(
            "Invalid or missing {} entry ExtIDs".format(EntryType.Create.value)
        )


def validate_did_update_ext_ids_v100(ext_ids):
    """
    Validates the ExtIDs of a DIDUpdate entry.

    Parameters
    ----------
    ext_ids: list of bytes
        The ExtIDs of the entry

    Returns
    -------
    bool
        True if the ExtIDs are valid, False otherwise.
    """
    if (
        _validate_ext_ids_length(ext_ids, 4)
        and _validate_entry_type(ext_ids, EntryType.Update)
        and _validate_schema_version(ext_ids, ENTRY_SCHEMA_V100)
        and _validate_key_identifier(ext_ids)
    ):
        return True
    return False


def validate_did_method_version_upgrade_ext_ids_v100(ext_ids):
    """
    Validates the ExtIDs of a DIDMethodVersionUpgrade entry.

    Parameters
    ----------
    ext_ids: list of bytes
        The ExtIDs of the entry

    Returns
    -------
    bool
        True if the ExtIDs are valid, False otherwise.
    """
    if (
        _validate_ext_ids_length(ext_ids, 4)
        and _validate_entry_type(ext_ids, EntryType.VersionUpgrade)
        and _validate_schema_version(ext_ids, ENTRY_SCHEMA_V100)
        and _validate_key_identifier(ext_ids)
    ):
        return True
    else:
        return False


def validate_did_deactivation_ext_ids_v100(ext_ids):
    """
    Validates the ExtIDs of a DIDDeactivation entry.

    Parameters
    ----------
    ext_ids: list of bytes
        The ExtIDs of the entry

    Returns
    -------
    bool
        True if the ExtIDs are valid, False otherwise.
    """
    if (
        _validate_ext_ids_length(ext_ids, 4)
        and _validate_entry_type(ext_ids, EntryType.Deactivation)
        and _validate_schema_version(ext_ids, ENTRY_SCHEMA_V100)
        and _validate_key_identifier(ext_ids)
    ):
        return True
    else:
        return False


def _validate_ext_ids_length(ext_ids, min_length):
    return len(ext_ids) >= min_length


def _validate_entry_type(ext_ids, entry_type):
    try:
        return ext_ids[0].decode() == entry_type.value
    except UnicodeDecodeError:
        return False


def _validate_schema_version(ext_ids, version):
    try:
        return ext_ids[1].decode() == version
    except UnicodeDecodeError:
        return False


def _validate_key_identifier(ext_ids):
    try:
        return (
            re.match(
                r"^{}:[0-9a-f]{{64}}#[a-zA-Z0-9-]+$".format(DID_METHOD_NAME),
                ext_ids[2].decode(),
            )
            is not None
        )
    except UnicodeDecodeError:
        return False
