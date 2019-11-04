import hashlib
import operator as op

from factom_did.client.blockchain import record_entry
from factom_did.client.constants import ENTRY_SCHEMA_V100
from factom_did.client.enums import EntryType


class DIDDeactivator:
    """
    Facilitates the creation of a DIDDeactivation entry.

    Attributes
    ----------
    did: client.did.DID
        The DID object to update
    """

    def __init__(self, did):
        self.did = did
        self.signing_key = sorted(
            self.did.management_keys, key=op.attrgetter("priority")
        )[0]

        assert (
            self.signing_key.priority == 0
        ), "Deactivation of a DID requires the availability of a management key with priority 0."

    def export_entry_data(self):
        """
        Constructs a signed DIDDeactivation entry ready for recording on-chain.

        Returns
        -------
        dict
            A dictionary with ExtIDs and content for the entry
        """
        data_to_sign = "".join(
            [
                EntryType.Deactivation.value,
                ENTRY_SCHEMA_V100,
                self.signing_key.full_id(self.did.id),
            ]
        )
        signature = self.signing_key.sign(
            hashlib.sha256(data_to_sign.encode("utf-8")).digest()
        )

        ext_ids = [
            EntryType.Deactivation.value.encode("utf-8"),
            ENTRY_SCHEMA_V100.encode("utf-8"),
            self.signing_key.full_id(self.did.id).encode("utf-8"),
            signature,
        ]

        # The content of the DIDDeactivation entry is empty
        return {"ext_ids": ext_ids, "content": b""}

    def record_on_chain(self, factomd, walletd, ec_address, verbose=False):
        """
        Attempts to record the DIDDeactivation entry on-chain.

        Parameters
        ----------
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
            If the entry cannot be recorded
        """
        record_entry(
            self.did.get_chain(),
            self.export_entry_data(),
            factomd,
            walletd,
            ec_address,
            verbose,
        )
