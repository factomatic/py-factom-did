import codecs
import hashlib
import json
import os
import re

from encryptor import encrypt_keys
from enums import SignatureType, EntryType, PurposeType
from keys import generate_key_pair
from models import ManagementKeyModel, DidKeyModel, ServiceModel

__all__ = ['DID', 'SignatureType', 'PurposeType']

ENTRY_SCHEMA_VERSION = '1.0.0'
DID_METHOD_SPEC_VERSION = '0.1.0'
ENTRY_SIZE_LIMIT = 10275


class DID:
    def __init__(self):
        self.id = self._generate_id()
        self.management_keys = []
        self.did_keys = []
        self.services = []
        self.used_key_aliases = set()
        self.used_service_aliases = set()

    def add_management_key(self, alias, priority, signature_type=SignatureType.EdDSA.value, controller=None):
        """
        Creates a new management key for the DID.

        Parameters
        ----------
        alias: str
            A human-readable nickname for the key. It should be unique across the keys defined in the DID document.
        priority: number
            A positive integer showing the hierarchical level of the key. The key(s) with priority 1
            overrides any key with priority greater than 1.
        signature_type: SignatureType, optional (default is EdDSA)
            Identifies the type of signature to be used when creating the key.
        controller: str, optional (default is None)
            An entity that will be making the signatures. It must be a valid DID. If the argument is not passed in,
            the default value is used which is the current DID itself.
        """

        if not controller:
            controller = self.id

        self._validate_key_input_params(alias, signature_type, controller)

        key_pair = generate_key_pair(signature_type)
        self.management_keys.append(ManagementKeyModel(alias, priority, signature_type, controller,
                                                       key_pair.public_key, key_pair.private_key))

    def add_did_key(self, alias, purpose, signature_type=SignatureType.EdDSA.value,
                    controller=None, priority_requirement=None):
        """
        Creates a new DID key for the DID.

        Parameters
        ----------
        alias: str
            A human-readable nickname for the key. It should be unique across the keys defined in the DID document.
        purpose: PurposeType[]
            A list of PurposeTypes showing what purpose(s) the key serves. (PublicKey, AuthenticationKey or both)
        signature_type: SignatureType, optional (default is EdDSA)
            Identifies the type of signature to be used when creating the key.
        controller: str, optional (default is None)
            An entity that will be making the signatures. It must be a valid DID. If the argument is not passed in,
            the default value is used which is the current DID itself.
        priority_requirement: number, optional (default is None)
            A positive integer showing the minimum hierarchical level a key must have in order to remove this key.
        """

        if not controller:
            controller = self.id

        self._validate_key_input_params(alias, signature_type, controller)

        key_pair = generate_key_pair(type)
        self.did_keys.append(DidKeyModel(alias, set(purpose), type, controller,
                                         key_pair.public_key, key_pair.private_key, priority_requirement))

    def add_service(self, alias, service_type, endpoint, priority_requirement=None):
        """
        Adds a new service to the DID Document.

        Parameters
        ----------
        alias: str
            A human-readable nickname for the service endpoint. It should be unique across the services
            defined in the DID document.
        service_type: str
            Type of the service endpoint.
        endpoint: str
            A service endpoint may represent any type of service the subject wishes to advertise,
            including decentralized identity management services for further discovery,
            authentication, authorization, or interaction.
            The service endpoint must be a valid URL.
        priority_requirement: number, optional (default is None)
            A positive integer showing the minimum hierarchical level a key must have in order to remove this service.
        """

        self._validate_service_input_params(service_type, endpoint, alias)
        self.services.append(ServiceModel(alias, service_type, endpoint, priority_requirement))

    def export_entry_data(self):
        """
        Exports content that can be recorded on-chain to create the DID.

        Returns
        -------
        dict
            a dictionary with the ExtIDs and entry content of strings used that are the header columns

        Raises
        ------
        RuntimeError
            If the entry size exceeds the entry size limit.
        """

        entry_content = json.dumps(self._get_did_document())
        entry_type = EntryType.Create.value

        entry_size = self._calculate_entry_size(
            [self.nonce],
            [entry_type, ENTRY_SCHEMA_VERSION],
            entry_content)

        if entry_size > ENTRY_SIZE_LIMIT:
            raise RuntimeError('You have exceeded the entry size limit! Please remove some of your keys or services.')

        return {
            'ext_ids': [entry_type, ENTRY_SCHEMA_VERSION, self.nonce],
            'content': entry_content
        }

    def export_encrypted_keys(self, password):
        """
        Returns encrypted keys cipher text
        """

        return encrypt_keys(self.public_keys, password)

    def _get_did_document(self):
        """
        Returns DID Document
        """

        public_keys = list(map(self._build_key_entry_object, self.public_keys))
        authentication_keys = list(map(self._build_key_entry_object, self.authentication_keys))
        services = list(map(self._build_service_entry_object, self.services))

        return {
            '@context': 'https://w3id.org/did/v1',
            'id': self.id,
            'publicKey': public_keys,
            'authentication': authentication_keys,
            'service': services
        }

    def _generate_id(self):
        """
        Generates new DID Id

        :return: did_id: str
        """

        self.nonce = codecs.encode(os.urandom(32), 'hex').decode()
        chain_id = self._calculate_chain_id([EntryType.Create.value, ENTRY_SCHEMA_VERSION, self.nonce])
        did_id = 'did:fctr:{}'.format(chain_id)
        return did_id

    def _build_key_entry_object(self, key):
        """
        Builds a key object to include in an entry

        :type key: KeyModel
        """

        return {
            'id': '{}#{}'.format(self.id, key.alias),
            'type': '{}VerificationKey'.format(key.signature_type),
            'controller': key.controller,
            'publicKeyBase58': str(key.public_key, 'utf8')
        }

    def _build_service_entry_object(self, service):
        """
        Builds a key object to include in an entry

        :type service: ServiceModel
        """

        return {
            'id': '{}#{}'.format(self.id, service.alias),
            'type': service.service_type,
            'serviceEndpoint': service.endpoint
        }

    @staticmethod
    def _calculate_chain_id(ext_ids):
        """
        Calculates chain id by hashing each ExtID, joining the hashes into a byte array and hashing the array

        :type ext_ids: Array
        :return full_hash_hex: str
        """

        ext_ids_hash_bytes = bytearray(b'')
        for ext_id in ext_ids:
            ext_ids_hash_bytes.extend(hashlib.sha256(bytes(ext_id, 'utf-8')).digest())

        return hashlib.sha256(ext_ids_hash_bytes).hexdigest()

    def _validate_key_input_params(self, alias, signature_type, controller):
        """
         Validates public and authentication key input parameters

         :type alias: str
         :type signature_type: SignatureType
         :type controller: str
        """

        if not re.match("^[a-z0-9-]{1,32}$", alias):
            raise ValueError('Alias must not be more than 32 characters long and must contain only lower-case '
                             'letters, digits and hyphens.')

        if alias in self.used_key_aliases:
            raise ValueError('The given key alias "{}" has already been used.'.format(alias))

        self.used_key_aliases.add(alias)

        if signature_type not in (SignatureType.ECDSA.value, SignatureType.EdDSA.value, SignatureType.RSA.value):
            raise ValueError('Type must be a valid signature type.')

        if not re.match("^did:fctr:[a-f0-9]{64}$", controller):
            raise ValueError('Controller must be a valid DID.')

    def _validate_service_input_params(self, service_type, endpoint, alias):
        """
        Validates public and authentication key input parameters

        :type service_type: str
        :type endpoint: str
        :type alias: str
        """

        if len(service_type) == 0:
            raise ValueError('Type is required.')

        if not re.match("^(http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?$", endpoint):
            raise ValueError('Endpoint must be a valid URL address starting with http:// or https://.')

        if not re.match("^[a-z0-9-]{1,32}$", alias):
            raise ValueError('Alias must not be more than 32 characters long and must contain only lower-case '
                             'letters, digits and hyphens.')

        if alias in self.used_service_aliases:
            raise ValueError('The given service alias "{}" has already been used.'.format(alias))

        self.used_service_aliases.add(alias)

    @staticmethod
    def _calculate_entry_size(hex_ext_ids, utf8_ext_ids, content):
        """
        Calculates entry size in bytes

        :type hex_ext_ids: Array
        :type utf8_ext_ids: Array
        :type content: str
        :return total_entry_size: number
        """

        total_entry_size = 0
        fixed_header_size = 35
        total_entry_size += fixed_header_size + 2*len(hex_ext_ids) + 2*len(utf8_ext_ids)

        for ext_id in hex_ext_ids:
            total_entry_size += len(ext_id) / 2

        for ext_id in utf8_ext_ids:
            total_entry_size += len(bytes(ext_id, 'utf-8'))

        total_entry_size += len(bytes(content, 'utf-8'))
        return total_entry_size
