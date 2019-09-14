import hashlib
import re

from factom.exceptions import FactomAPIError


def calculate_entry_size(ext_ids, content):
    """
    Calculates entry size in bytes.

    Parameters
    ----------
    ext_ids: bytes[] or str[]
    content: bytes or str

    Returns
    -------
    int
        A total size of the entry in bytes.
    """

    total_entry_size = 0
    fixed_header_size = 35
    total_entry_size += fixed_header_size + 2 * len(ext_ids)

    for ext_id in ext_ids:
        if type(ext_id) is bytes:
            total_entry_size += len(ext_id)
        else:
            # If the ExtID is not bytes, it's assumed to be a hex string
            assert (
                re.match("[0-9a-f]+", ext_id) is not None
            ), "ExtID must be bytes or hex string"
            total_entry_size += len(ext_id) / 2

    if type(content) is bytes:
        total_entry_size += len(content)
    else:
        assert (
            re.match("[0-9a-f]+", content) is not None
        ), "Content must be bytes or hex string"
        total_entry_size += len(content) / 2

    return total_entry_size


def calculate_chain_id(ext_ids):
    """
    Calculates chain id by hashing each ExtID, joining the hashes into a byte array and hashing the array.

    Parameters
    ----------
    ext_ids: list
        A list of ExtIDs.

    Returns
    -------
    str
        A chain id.
    """

    ext_ids_hash_bytes = bytearray(b"")
    for ext_id in ext_ids:
        if type(ext_id) is bytes:
            ext_ids_hash_bytes.extend(hashlib.sha256(ext_id).digest())
        else:
            ext_ids_hash_bytes.extend(hashlib.sha256(bytes(ext_id, "utf-8")).digest())

    return hashlib.sha256(ext_ids_hash_bytes).hexdigest()


def record_entry_on_chain(entry_data, factomd, walletd, ec_address, verbose=False):
    """
    Attempts to record the DID document on-chain.

    Parameters
    ----------
    entry_data: dict
        A dictionary with two keys: ext_ids and content. The value of ext_ids must be a list
        of bytes or hex encoded string, while the value of content must be bytes or hex encoded str.
    factomd: obj
        Factomd instance, instantiated from the Python factom-api package.
    walletd: obj
        Factom walletd instance, instantiated from the Python factom-api package.
    ec_address: str
        EC address used to pay for the chain & entry creation.
    verbose: bool, optional
        If true, display the contents of the entry that will be recorded
        on-chain.

    Raises
    ------
        RuntimeError
            If the chain cannot be created
    """

    from pprint import pprint

    if verbose:
        pprint(entry_data)

    try:
        walletd.new_chain(
            factomd, entry_data["ext_ids"], entry_data["content"], ec_address=ec_address
        )
    except FactomAPIError as e:
        raise RuntimeError(
            "Failed while trying to record DID data on-chain: {}".format(e.data)
        )
