import os
from pprint import pprint
import time

from factom import Factomd, FactomWalletd

from factom_did.client.constants import DID_METHOD_NAME
from factom_did.client.did import DID, KeyType, DIDKeyPurpose
from factom_did.client.encryptor import (
    decrypt_keys_from_str,
    decrypt_keys_from_json_str,
    decrypt_keys_from_json_file,
)


# NOTE: You must set an EC_ADDR environment variable, which points to a funded
# EC address, in order to be able to record DIDs on-chain
factomd = Factomd()
walletd = FactomWalletd()
ec_address = os.environ.get("EC_ADDR")


def create_new_did():
    # New management key with default key type and controller
    management_key_1_alias = "my-first-management-key"
    management_key_1_priority = 0

    # New management key with specified key type and controller
    management_key_2_alias = "my-second-management-key"
    management_key_2_priority = 2
    management_key_2_type = KeyType.ECDSA
    management_key_2_controller = "{}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005".format(
        DID_METHOD_NAME
    )

    # New public key with default key type and controller
    did_key_1_alias = "my-did-key-1"
    did_key_1_purpose = [DIDKeyPurpose.PublicKey]

    # New authentication key with specified key type
    did_key_2_alias = "my-did-key-2"
    did_key_2_purpose = [DIDKeyPurpose.AuthenticationKey]
    did_key_2_type = KeyType.RSA

    # New public and authentication key with specified key type, controller and priority requirement
    did_key_3_alias = "my-did-key-3"
    did_key_3_purpose = [DIDKeyPurpose.PublicKey, DIDKeyPurpose.AuthenticationKey]
    did_key_3_type = KeyType.EdDSA
    did_key_3_controller = "{}:d3936b2f0bdd45fe71d7156e835434b7970afd78868076f56654d05f838b8005".format(
        DID_METHOD_NAME
    )
    did_key_3_priority_requirement = 2

    # New service
    service_alias = "my-photo-service"
    service_type = "PhotoStreamService"
    service_endpoint = "https://myphoto.com"
    service_priority_requirement = 1
    service_custom_fields = {
        "description": "A photo stream service",
        "spamCost": {"amount": "0.50", "currency": "USD"},
    }

    new_did = (
        DID()
        # Can be mainnet/testnet or omitted entirely, in which case no network specifier will be added to the DID
        .testnet()
        .management_key(management_key_1_alias, management_key_1_priority)
        .management_key(
            management_key_2_alias,
            management_key_2_priority,
            management_key_2_type,
            management_key_2_controller,
        )
        .did_key(did_key_1_alias, did_key_1_purpose)
        .did_key(did_key_2_alias, did_key_2_purpose, did_key_2_type)
        .did_key(
            did_key_3_alias,
            did_key_3_purpose,
            did_key_3_type,
            did_key_3_controller,
            did_key_3_priority_requirement,
        )
        .service(
            service_alias,
            service_type,
            service_endpoint,
            service_priority_requirement,
            service_custom_fields,
        )
    )

    return new_did


def record_did_on_chain(did):
    # Show the data to be recorded for illustration purposes
    did.record_on_chain(factomd, walletd, ec_address, verbose=True)


def update_existing_did(did):
    did.update().add_did_key(
        "my-did-key-4", DIDKeyPurpose.AuthenticationKey
    ).add_did_key(
        "my-did-key-5", [DIDKeyPurpose.AuthenticationKey, DIDKeyPurpose.PublicKey]
    ).add_management_key(
        "my-management-key-42", 1
    ).add_service(
        "gmail-service", "email-service", "https://gmail.com"
    ).revoke_did_key(
        "my-did-key-2"
    ).rotate_did_key(
        "my-did-key-3"
    ).rotate_management_key(
        "my-first-management-key"
    ).revoke_management_key(
        "my-second-management-key"
    ).revoke_service(
        "my-photo-service"
    ).record_on_chain(
        factomd, walletd, ec_address, verbose=True
    )


def encrypt_keys_as_str_and_decrypt():
    new_did = create_new_did()
    keys_cipher_text = new_did.export_encrypted_keys_as_str("1234")
    print(
        "-----------------------------------Encrypted---------------------------------------"
    )
    print(keys_cipher_text)

    decrypted_keys = decrypt_keys_from_str(keys_cipher_text, "1234")
    print(
        "-----------------------------------Decrypted---------------------------------------"
    )
    pprint(decrypted_keys)

    decrypted_management_keys = decrypted_keys.get("managementKeys")
    first_management_key_alias = list(decrypted_management_keys.keys())[0]
    first_management_key_private_key = decrypted_management_keys[
        first_management_key_alias
    ]
    print(
        "{} -> {}".format(first_management_key_alias, first_management_key_private_key)
    )


def encrypt_keys_as_json_and_decrypt():
    new_did = create_new_did()
    keys_json = new_did.export_encrypted_keys_as_json("1234")
    print(
        "-----------------------------------Encrypted---------------------------------------"
    )
    pprint(keys_json)

    decrypted_keys = decrypt_keys_from_json_str(keys_json, "1234")
    print(
        "-----------------------------------Decrypted---------------------------------------"
    )
    pprint(decrypted_keys)


def decrypt_keys_from_file():
    """
    Decrypt keys from JSON file with a schema compatible to the one in
    DID.export_encrypted_keys_as_json()
    """

    file_path = os.path.join("examples", "paper-did-UTC--2019-09-11T07_42_16.244Z.txt")
    password = "123qweASD!@#"
    decrypted_keys = decrypt_keys_from_json_file(file_path, password)
    pprint(decrypted_keys)


if __name__ == "__main__":
    did = create_new_did()
    record_did_on_chain(did)
    time.sleep(1)
    update_existing_did(did)
