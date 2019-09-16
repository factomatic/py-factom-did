from base64 import urlsafe_b64encode
import json
import os
import re


from did.blockchain import calculate_chain_id, calculate_entry_size, create_chain
from did.constants import *
from did.encryptor import encrypt_keys
from did.enums import SignatureType, EntryType, DIDKeyPurpose
from did.keys import ManagementKey, DIDKey
from did.service import Service
from did.updater import DIDUpdater

__all__ = ["DID", "SignatureType", "DIDKeyPurpose"]


class DID:
    """
    Enables the construction of a DID document, by facilitating the construction of management keys and DID keys and the
    addition of services. Allows exporting of the resulting DID object into a format suitable for recording on the
    Factom blockchain.

    Provides encryption functionality of private keys for the DID and their export to a string or to a JSON file.

    Attributes
    ----------
    did: str, optional
        The decentralized identifier, a 32 byte hexadecimal string
    management_keys: ManagementKey[], optional
        A list of management keys
    did_keys: DIDKey[], optional
        A list of DID keys
    services: Service[], optional
        A list of services
    """

    def __init__(self, did=None, management_keys=None, did_keys=None, services=None):
        self.id = (
            self._generate_did() if did is None or not self.is_valid_did(did) else did
        )
        self.management_keys = [] if management_keys is None else management_keys
        self.did_keys = [] if did_keys is None else did_keys
        self.services = [] if services is None else services

        self.used_key_aliases = set()
        self.used_service_aliases = set()

        for key in self.management_keys:
            self._check_alias_is_unique_and_add_to_used(
                self.used_key_aliases, key.alias
            )
        for key in self.did_keys:
            self._check_alias_is_unique_and_add_to_used(
                self.used_key_aliases, key.alias
            )
        for service in self.services:
            self._check_alias_is_unique_and_add_to_used(
                self.used_service_aliases, service.alias
            )

    def get_chain(self):
        """
        Returns
        -------
        str
            The chain ID where this DID is (or will be) stored
        """
        # Since we do a validation of the DID in the constructor (or add it automatically, if it's not provided),
        # we have a guarantee that it will be well-formed, hence no need for exception checking here
        return self.id.split(":")[2]

    def update(self):
        """
        Returns
        -------
        did.did.DID
            The updated DID object
        """
        if not self.management_keys:
            raise RuntimeError("Cannot update DID without management keys.")
        return DIDUpdater(self)

    def management_key(
        self,
        alias,
        priority,
        signature_type=SignatureType.EdDSA.value,
        controller=None,
        priority_requirement=None,
    ):
        """
        Creates a new management key for the DID.

        Parameters
        ----------
        alias: str
            A human-readable nickname for the key. It should be unique across the keys defined in the DID document.
        priority: int
            A non-negative integer showing the hierarchical level of the key. Keys with lower priority
            override keys with higher priority.
        signature_type: SignatureType, optional
            Identifies the type of signature that the key pair can be used to generate and verify.
        controller: str, optional
            An entity that controls the key. It must be a valid DID. If the argument is not passed in,
            the default value is used which is the current DID itself.
        priority_requirement: int, optional
            A non-negative integer showing the minimum hierarchical level a key must have in order to remove this key.
        """

        if not controller:
            controller = self.id

        key = ManagementKey(
            alias, priority, signature_type, controller, priority_requirement
        )
        self._check_alias_is_unique_and_add_to_used(self.used_key_aliases, alias)

        self.management_keys.append(key)

        return self

    def did_key(
        self,
        alias,
        purpose,
        signature_type=SignatureType.EdDSA.value,
        controller=None,
        priority_requirement=None,
    ):
        """
        Creates a new DID key for the DID.

        Parameters
        ----------
        alias: str
            A human-readable nickname for the key. It should be unique across the keys defined in the DID document.
        purpose: DIDKeyPurpose or DIDKeyPurpose[]
            Shows what purpose(s) the key serves. (PublicKey, AuthenticationKey or both)
        signature_type: SignatureType, optional
            Identifies the type of signature to be used when creating the key.
        controller: str, optional
            An entity that will be making the signatures. It must be a valid DID. If the argument is not passed in,
            the default value is used which is the current DID itself.
        priority_requirement: int, optional
            A non-negative integer showing the minimum hierarchical level a key must have in order to remove this key.
        """

        if not controller:
            controller = self.id

        key = DIDKey(alias, purpose, signature_type, controller, priority_requirement)
        self._check_alias_is_unique_and_add_to_used(self.used_key_aliases, alias)

        self.did_keys.append(key)

        return self

    def service(self, alias, service_type, endpoint, priority_requirement=None):
        """
        Adds a new service to the DID Document.

        Parameters
        ----------
        alias: str
            A human-readable nickname for the service endpoint. It should be unique across the services defined in the
            DID document.
        service_type: str
            Type of the service endpoint.
        endpoint: str
            A service endpoint may represent any type of service the subject wishes to advertise, including
            decentralized identity management services for further discovery, authentication, authorization, or
            interaction.
            The service endpoint must be a valid URL.
        priority_requirement: int, optional
            A non-negative integer showing the minimum hierarchical level a key must have in order to remove this
            service.
        """

        service = Service(alias, service_type, endpoint, priority_requirement)
        self._check_alias_is_unique_and_add_to_used(self.used_service_aliases, alias)

        self.services.append(service)

        return self

    def export_entry_data(self):
        """
        Exports content that can be recorded on-chain to create the DID.

        Returns
        -------
        dict
            A dictionary with the ExtIDs and entry content of strings used that are the header columns.

        Raises
        ------
        ValueError
            If there are no management keys.
            If there is no management key with priority 0.
            If the entry size exceeds the entry size limit.
        """

        management_keys = list(
            map(lambda k: k.to_entry_dict(self.id), self.management_keys)
        )

        if len(management_keys) < 1:
            raise ValueError("The DID must have at least one management key.")
        if not any(map(lambda key: key["priority"] == 0, management_keys)):
            raise ValueError("At least one management key must have priority 0.")

        ext_ids = [
            EntryType.Create.value.encode("utf-8"),
            ENTRY_SCHEMA_VERSION.encode("utf-8"),
            self.nonce,
        ]
        entry_content = json.dumps(self._get_did_document()).encode("utf-8")

        entry_size = calculate_entry_size(ext_ids, entry_content)

        if entry_size > ENTRY_SIZE_LIMIT:
            raise RuntimeError(
                "You have exceeded the entry size limit! Please "
                "remove some of your keys or services."
            )

        return {"ext_ids": ext_ids, "content": entry_content}

    def export_encrypted_keys_as_str(self, password):
        """
        Exports encrypted keys cipher text.

        Parameters
        ----------
        password: str
            A password to use for the encryption of the keys.

        Returns
        -------
        str
            Encrypted keys cipher text.
        """

        encryption_result = encrypt_keys(self.management_keys, self.did_keys, password)
        cipher_text_b64 = urlsafe_b64encode(
            encryption_result["salt"]
            + encryption_result["iv"]
            + encryption_result["data"]
        )
        return str(cipher_text_b64, "utf8")

    def export_encrypted_keys_as_json(self, password):
        """
        Exports encrypted keys as JSON.

        Parameters
        ----------
        password: str
            A password to use for the encryption of the keys.

        Returns
        -------
        str
            Encrypted keys JSON.
        """

        encryption_result = encrypt_keys(self.management_keys, self.did_keys, password)
        return json.dumps(
            {
                "data": str(urlsafe_b64encode(encryption_result["data"]), "utf8"),
                "encryptionAlgo": {
                    "name": "AES-GCM",
                    "iv": str(urlsafe_b64encode(encryption_result["iv"]), "utf8"),
                    "salt": str(urlsafe_b64encode(encryption_result["salt"]), "utf8"),
                    "tagLength": 128,
                },
                "did": self.id,
            }
        )

    def record_on_chain(self, factomd, walletd, ec_address, verbose=False):
        """
        Attempts to create the DIDManagement chain.

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
                If the chain cannot be created
        """

        create_chain(self.export_entry_data(), factomd, walletd, ec_address, verbose)

    @staticmethod
    def is_valid_did(did):
        return re.match("^{}:[a-f0-9]{{64}}$".format(DID_METHOD_NAME), did) is not None

    def _get_did_document(self):
        """
        Builds a DID Document.

        Returns
        -------
        dict
            A dictionary with the DID Document properties.
        """

        management_keys = list(
            map(lambda k: k.to_entry_dict(self.id), self.management_keys)
        )

        did_document = {
            "didMethodVersion": DID_METHOD_SPEC_VERSION,
            "managementKey": management_keys,
        }

        did_keys = list(map(lambda k: k.to_entry_dict(self.id), self.did_keys))
        if len(did_keys) > 0:
            did_document["didKey"] = did_keys

        services = list(map(lambda s: s.to_entry_dict(self.id), self.services))
        if len(services) > 0:
            did_document["service"] = services

        return did_document

    def _generate_did(self):
        """
        Generates a new DID Id.

        Returns
        -------
        str
            A DID Id.
        """

        self.nonce = os.urandom(32)
        chain_id = calculate_chain_id(
            [EntryType.Create.value, ENTRY_SCHEMA_VERSION, self.nonce]
        )
        did_id = "{}:{}".format(DID_METHOD_NAME, chain_id)
        return did_id

    @staticmethod
    def _check_alias_is_unique_and_add_to_used(used_aliases, alias):
        if alias in used_aliases:
            raise ValueError('Duplicate key alias "{}" detected.'.format(alias))
        used_aliases.add(alias)
