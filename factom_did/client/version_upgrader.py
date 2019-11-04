import hashlib
import json
import operator as op
from packaging import version

from factom_did.client.blockchain import record_entry
from factom_did.client.constants import ENTRY_SCHEMA_V100
from factom_did.client.enums import EntryType


class DIDVersionUpgrader:
    """
    Facilitates the creation of an DIDMethodVersionUpgrade entry for an existing DID.

    Attributes
    ----------
    did: client.did.DID
        The DID object to update
    new_spec_version: str
        The new version to upgrade to

    Raises
    ------
    ValueError
        If the new version is not an upgrade on the current version
    """

    def __init__(self, did, new_spec_version):
        if version.parse(did.spec_version) >= version.parse(new_spec_version):
            raise ValueError("New version must be an upgrade on old version")
        self.did = did
        self.new_spec_version = new_spec_version

    def export_entry_data(self):
        """
        Constructs a signed DIDMethodVersionUpgrade entry ready for recording on-chain.

        Returns
        -------
        dict
            A dictionary with ExtIDs and content for the entry
        """
        # Sign with the management key with least priority
        signing_key = sorted(
            self.did.management_keys, key=op.attrgetter("priority"), reverse=True
        )[0]

        entry_content = json.dumps({"didMethodVersion": self.new_spec_version}).replace(
            " ", ""
        )
        data_to_sign = "".join(
            [
                EntryType.VersionUpgrade.value,
                ENTRY_SCHEMA_V100,
                signing_key.full_id(self.did.id),
                entry_content,
            ]
        )
        signature = signing_key.sign(
            hashlib.sha256(data_to_sign.encode("utf-8")).digest()
        )

        ext_ids = [
            EntryType.VersionUpgrade.value.encode("utf-8"),
            ENTRY_SCHEMA_V100.encode("utf-8"),
            signing_key.full_id(self.did.id).encode("utf-8"),
            signature,
        ]

        return {"ext_ids": ext_ids, "content": entry_content.encode("utf-8")}

    def record_on_chain(self, factomd, walletd, ec_address, verbose=False):
        """
        Attempts to record the DIDMethodVersionUpgrade entry on-chain.

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
