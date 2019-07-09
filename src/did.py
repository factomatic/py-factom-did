import codecs
import hashlib
import json
import os
import re

from encryptor import encrypt_keys
from enums import SignatureType, EntryType
from keys import generate_key_pair
from models import KeyModel, ServiceModel

__all__ = ['DID', 'SignatureType']

DID_METHOD_SPEC_VERSION = '1.0'
ENTRY_SIZE_LIMIT = 10275
DEFAULT_ALIAS = 'defaultpubkey'


class DID:
    def __init__(self):
        self.id = self._generate_id()
        self.public_keys = []
        self.authentication_keys = []
        self.services = []
        self.used_key_aliases = set()
        self.used_service_aliases = set()

    def add_public_key(self, alias=DEFAULT_ALIAS, signature_type=SignatureType.EdDSA.value, controller=None):
        """
        Adds new public key to public_keys array

        :type alias: str
        :type signature_type: SignatureType
        :type controller: str
        """

        if not controller:
            controller = self.id

        self._validate_key_input_params(alias, signature_type, controller)

        key_pair = generate_key_pair(signature_type)
        self.public_keys.append(KeyModel(alias, signature_type, controller, key_pair.public_key, key_pair.private_key))

    def add_authentication_key(self, alias, signature_type=SignatureType.EdDSA.value, controller=None):
        """
        Adds new authentication key to authentication_keys array

        :type alias: str
        :type signature_type: SignatureType
        :type controller: str
        """

        if not controller:
            controller = self.id

        self._validate_key_input_params(alias, signature_type, controller)

        key_pair = generate_key_pair(signature_type)
        self.authentication_keys.append(KeyModel(alias, signature_type, controller, key_pair.public_key, key_pair.private_key))

    def add_service(self, service_type, endpoint, alias):
        """
        Adds new service to services array

        :type service_type: str
        :type endpoint: str
        :type alias: str
        """

        self._validate_service_input_params(service_type, endpoint, alias)
        self.services.append(ServiceModel(service_type, endpoint, alias))

    def export_entry_data(self):
        """
        Returns a dictionary with the ExtIDs and entry content that can be recorded on-chain to create the DID
        """

        entry_content = json.dumps(self._get_did_document())
        entry_type = EntryType.Create.value

        entry_size = self._calculate_entry_size(
            [self.nonce],
            [entry_type, DID_METHOD_SPEC_VERSION],
            json.dumps(entry_content))

        if entry_size > ENTRY_SIZE_LIMIT:
            raise RuntimeError('You have exceeded the entry size limit! Please remove some of your keys or services.')

        return {
            'ext_ids': [entry_type, DID_METHOD_SPEC_VERSION, self.nonce],
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
        chain_id = self._calculate_chain_id([EntryType.Create.value, DID_METHOD_SPEC_VERSION, self.nonce])
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
