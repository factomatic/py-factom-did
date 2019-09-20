import re

from client.constants import DID_METHOD_NAME
from client.enums import EntryType
from resolver.exceptions import MalformedDIDManagementEntry


class DeactivationEntryContentValidator:
    @staticmethod
    def validate(content):
        if content:
            return False
        return True


def validate_did_management_ext_ids_v100(ext_ids):
    """
    Validates the ExtIDs of a DIDManagement entry.

    Parameters
    ----------
    ext_ids: list of str
        The ExtIDs of the entry

    Raises
    ------
    MalformedDIDManagementEntry
        If the ExtIDs are not valid.
    """

    if all(
        [
            _validate_ext_ids_length(ext_ids, 2),
            _validate_entry_type(ext_ids, EntryType.Create),
            _validate_schema_version(ext_ids),
        ]
    ):
        return True
    else:
        raise MalformedDIDManagementEntry(
            "Invalid or missing {} entry ExtIDs".format(EntryType.Create.value)
        )


def validate_did_update_ext_ids_v100(ext_ids):
    """
    Validates the ExtIDs of a DIDUpdate entry.

    Parameters
    ----------
    ext_ids: list of str
        The ExtIDs of the entry

    Returns
    -------
    bool
        True if the ExtIDs are valid, False otherwise.
    """
    return (
        _validate_ext_ids_length(ext_ids, 4)
        and _validate_entry_type(ext_ids, EntryType.Update)
        and _validate_schema_version(ext_ids)
        and _validate_key_identifier(ext_ids)
        and _validate_signature_format(ext_ids)
    )


def validate_did_method_version_upgrade_ext_ids_v100(ext_ids):
    """
    Validates the ExtIDs of a DIDMethodVersionUpgrade entry.

    Parameters
    ----------
    ext_ids: list of str
        The ExtIDs of the entry

    Returns
    -------
    bool
        True if the ExtIDs are valid, False otherwise.
    """
    return (
        _validate_ext_ids_length(ext_ids, 4)
        and _validate_entry_type(ext_ids, EntryType.VersionUpgrade)
        and _validate_schema_version(ext_ids)
        and _validate_key_identifier(ext_ids)
        and _validate_signature_format(ext_ids)
    )


def validate_did_deactivation_ext_ids_v100(ext_ids):
    """
    Validates the ExtIDs of a DIDDeactivation entry.

    Parameters
    ----------
    ext_ids: list of str
        The ExtIDs of the entry

    Returns
    -------
    bool
        True if the ExtIDs are valid, False otherwise.
    """
    return (
        _validate_ext_ids_length(ext_ids, 4)
        and _validate_entry_type(ext_ids, EntryType.Deactivation)
        and _validate_schema_version(ext_ids)
        and _validate_key_identifier(ext_ids)
        and _validate_signature_format(ext_ids)
    )


def _validate_ext_ids_length(ext_ids, min_length):
    if len(ext_ids) < min_length:
        return False
    return True


def _validate_entry_type(ext_ids, entry_type):
    if ext_ids[0] != entry_type.value:
        return False
    return True


def _validate_schema_version(ext_ids):
    if re.match(r"^\d+\.\d+\.\d+$", ext_ids[1]) is None:
        return False
    return True


def _validate_key_identifier(ext_ids):
    if (
        re.match(
            r"^{}:[0-9a-f]{{64}}#[a-zA-Z0-9-]+$".format(DID_METHOD_NAME), ext_ids[2]
        )
        is None
    ):
        return False
    return True


def _validate_signature_format(ext_ids):
    if re.match(r"^0x[0-9a-f]+$", ext_ids[3]) is None:
        return False
    return True
