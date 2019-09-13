import hashlib

from factom.exceptions import FactomAPIError


def calculate_entry_size(hex_ext_ids, utf8_ext_ids, content):
    """
    Calculates entry size in bytes.

    Parameters
    ----------
    hex_ext_ids: list
    utf8_ext_ids: list
    content: str

    Returns
    -------
    int
        A total size of the entry in bytes.
    """

    total_entry_size = 0
    fixed_header_size = 35
    total_entry_size += fixed_header_size + 2 * len(hex_ext_ids) + 2 * len(utf8_ext_ids)

    for ext_id in hex_ext_ids:
        total_entry_size += len(ext_id) / 2

    for ext_id in utf8_ext_ids:
        total_entry_size += len(bytes(ext_id, "utf-8"))

    total_entry_size += len(bytes(content, "utf-8"))
    return total_entry_size


def calculate_chain_id(ext_ids):
    """
    Calculates chain id by hashing each ExtID, joining the hashes into a byte array and hashing the array.

    Parameters
    ----------
    ext_ids: list
        A list of ExtIds.

    Returns
    -------
    str
        A chain id.
    """

    ext_ids_hash_bytes = bytearray(b"")
    for ext_id in ext_ids:
        ext_ids_hash_bytes.extend(hashlib.sha256(bytes(ext_id, "utf-8")).digest())

    return hashlib.sha256(ext_ids_hash_bytes).hexdigest()


def record_entry_on_chain(entry_data, factomd, walletd, ec_address, verbose=False):
    """
    Attempts to record the DID document on-chain.

    Parameters
    ----------
    entry_data: dict
        A dictionary with two keys: ext_ids and content. The value of ext_ids is a list
        of str, while the value of content is a str.
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

    # Encode the entry data
    ext_ids = map(lambda x: x.encode("utf-8"), entry_data["ext_ids"])
    content = entry_data["content"].encode("utf-8")

    try:
        walletd.new_chain(factomd, ext_ids, content, ec_address=ec_address)
    except FactomAPIError as e:
        raise RuntimeError(
            "Failed while trying to record DID data on-chain: {}".format(e.data)
        )
