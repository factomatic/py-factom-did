import hashlib

from jsonschema.exceptions import ValidationError

from factom_did.client.constants import ENTRY_SCHEMA_V100
from factom_did.client.enums import EntryType
from factom_did.client.validators import validate_full_key_identifier
from factom_did.resolver.exceptions import MalformedDIDManagementEntry


class EmptyEntryContentValidator:
    @staticmethod
    def validate(content):
        if content:
            raise ValidationError("Invalid entry content: must be empty")


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
    return (
        _validate_ext_ids_length(ext_ids, 4)
        and _validate_entry_type(ext_ids, EntryType.Update)
        and _validate_schema_version(ext_ids, ENTRY_SCHEMA_V100)
        and _validate_key_identifier(ext_ids)
    )


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
    return (
        _validate_ext_ids_length(ext_ids, 4)
        and _validate_entry_type(ext_ids, EntryType.VersionUpgrade)
        and _validate_schema_version(ext_ids, ENTRY_SCHEMA_V100)
        and _validate_key_identifier(ext_ids)
    )


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
    return (
        _validate_ext_ids_length(ext_ids, 4)
        and _validate_entry_type(ext_ids, EntryType.Deactivation)
        and _validate_schema_version(ext_ids, ENTRY_SCHEMA_V100)
        and _validate_key_identifier(ext_ids)
    )


def validate_signature(ext_ids, content, signing_key):
    """
    Checks if the signature contained in the last element of ext_ids is valid.

    The signature is for a DIDUpdate, DIDMethodVersionUpgrade or DIDDeactivation entry and covers the content of the
    entry + the first 3 ext_ids. For more details on the signatures of these entries, refer to
    https://github.com/bi-foundation/FIS/blob/feature/DID/FIS/DID.md

    Parameters
    ----------
    ext_ids: list of bytes
    content: bytes
    signing_key: ManagementKey

    Returns
    -------
    bool
    """
    signed_data = bytearray()
    for i in range(3):
        signed_data.extend(ext_ids[i])
    signed_data.extend(content)
    return signing_key.verify(hashlib.sha256(signed_data).digest(), ext_ids[3])


def validate_management_key_id(key_id, chain_id):
    """
    Checks if the chain in the key_id matches the value supplied in chain_id.

    Parameters
    ----------
    key_id: str
        The well-formed full key identifier
    chain_id: str
        The chain ID

    Returns
    -------
    bool
    """
    # Due to prior validation of the entries, the key_id passed to this function is guaranteed to be a well-formed
    # full key identifier
    key_id_chain = key_id.split(":")[-1].split("#")[0]
    return key_id_chain == chain_id


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
        validate_full_key_identifier(ext_ids[2].decode())
    except (UnicodeDecodeError, ValueError):
        return False
    else:
        return True
