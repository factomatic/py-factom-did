import os
from pprint import pprint

from factom import Factomd, FactomWalletd

from did.did import DID, DID_METHOD_NAME, SignatureType, PurposeType
from did.encryptor import decrypt_keys_from_str, decrypt_keys_from_json_str, \
    decrypt_keys_from_json_file


factomd = Factomd()
walletd = FactomWalletd()
fct_address = 'FA2jK2HcLnRdS94dEcU27rF3meoJfpUcZPSinpb7AwQvPRY6RL1Q'
ec_address = 'EC3VjuH17eACyP22WwxPcqcbnVkE8QSd1HJP7MXDJkgR3hvaPBhP'


def create_new_did():
    new_did = DID()

    '''Add new management key with default signature type and controller'''
    management_key_1_alias = 'my-first-management-key'
    management_key_1_priority = 0
    new_did.add_management_key(management_key_1_alias, management_key_1_priority)

    '''Add new management key with specified signature type and controller'''
    management_key_2_alias = 'my-second-management-key'
    management_key_2_priority = 2
    management_key_2_signature_type = SignatureType.ECDSA.value
    management_key_2_controller = '{}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005'.format(DID_METHOD_NAME)
    new_did.add_management_key(management_key_2_alias, management_key_2_priority, management_key_2_signature_type,
                               management_key_2_controller)

    '''Add new public key with default signature type and controller'''
    did_key_1_alias = 'my-did-key-1'
    did_key_1_purpose = [PurposeType.PublicKey.value]
    new_did.add_did_key(did_key_1_alias, did_key_1_purpose)

    '''Add new authentication key with specified signature type'''
    did_key_2_alias = 'my-did-key-2'
    did_key_2_purpose = [PurposeType.AuthenticationKey.value]
    did_key_2_signature_type = SignatureType.RSA.value
    new_did.add_did_key(did_key_2_alias, did_key_2_purpose, did_key_2_signature_type)

    '''Add new both public and authentication key with specified signature type, controller and priority requirement'''
    did_key_3_alias = 'my-did-key-3'
    did_key_3_purpose = [PurposeType.PublicKey.value, PurposeType.AuthenticationKey.value]
    did_key_3_signature_type = SignatureType.EdDSA.value
    did_key_3_controller = '{}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005'.format(DID_METHOD_NAME)
    did_key_3_priority_requirement = 2
    new_did.add_did_key(did_key_3_alias, did_key_3_purpose, did_key_3_signature_type, did_key_3_controller,
                        did_key_3_priority_requirement)

    '''Add new service'''
    service_alias = 'my-photo-service'
    service_type = 'PhotoStreamService'
    service_endpoint = 'https://myphoto.com'
    new_did.add_service(service_alias, service_type, service_endpoint)

    return new_did


def record_did_on_chain():
    new_did = create_new_did()
    entry_data = new_did.export_entry_data()
    walletd.new_chain(factomd, entry_data['ext_ids'], entry_data['content'], ec_address=ec_address)
    pprint(entry_data)


def encrypt_keys_as_str_and_decrypt():
    new_did = create_new_did()
    keys_cipher_text = new_did.export_encrypted_keys_as_str('1234')
    print('-----------------------------------Encrypted---------------------------------------')
    print(keys_cipher_text)

    decrypted_keys = decrypt_keys_from_str(keys_cipher_text, '1234')
    print('-----------------------------------Decrypted---------------------------------------')
    pprint(decrypted_keys)
    pprint(decrypted_keys[0]['alias'])


def encrypt_keys_as_json_and_decrypt():
    new_did = create_new_did()
    keys_json = new_did.export_encrypted_keys_as_json('1234')
    print('-----------------------------------Encrypted---------------------------------------')
    pprint(keys_json)

    decrypted_keys = decrypt_keys_from_json_str(keys_json, '1234')
    print('-----------------------------------Decrypted---------------------------------------')
    pprint(decrypted_keys)
    pprint(decrypted_keys[0]['alias'])


def decrypt_keys_from_file():
    '''
    Decrypt keys from JSON file with a schema compatible to the one in
    DID.export_encrypted_keys_as_json()
    '''

    file_path = os.path.join(
        'examples',
        'paper-did-UTC--2019-08-06T10_51_19.432Z.txt')
    password = '123qweASD!@#'
    decrypted_keys = decrypt_keys_from_json_file(file_path, password)
    pprint(decrypted_keys)
    pprint(decrypted_keys[0]['privateKey'])


if __name__ == '__main__':
    did_object = create_new_did()
    pprint(did_object.export_entry_data())
