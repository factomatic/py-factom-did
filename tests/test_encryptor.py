import os
import pytest

from did.did import DID
from did.encryptor import (
    decrypt_keys_from_str,
    decrypt_keys_from_json_str,
    decrypt_keys_from_json_file,
)


@pytest.fixture
def did():
    return DID()


class TestEncryptor:
    def test_encrypt_as_str_and_decrypt(self, did):
        did.add_management_key("management-key", 1)
        generated_management_key = did.management_keys[0]

        password = "123456"
        encrypted_keys_cipher_b64 = did.export_encrypted_keys_as_str(password)
        decrypted_keys = decrypt_keys_from_str(encrypted_keys_cipher_b64, password)
        decrypted_management_key = decrypted_keys[0]

        assert generated_management_key.alias == decrypted_management_key["alias"]
        assert (
            generated_management_key.signature_type == decrypted_management_key["type"]
        )
        assert (
            str(generated_management_key.private_key, "utf8")
            == decrypted_management_key["privateKey"]
        )

    def test_encrypt_as_str_and_decrypt_with_invalid_password_throws_error(self, did):
        did.add_management_key("management-key", 1)

        password = "123456"
        encrypted_keys_cipher_b64 = did.export_encrypted_keys_as_str(password)

        invalid_password = "12345"
        with pytest.raises(ValueError):
            decrypt_keys_from_str(encrypted_keys_cipher_b64, invalid_password)

    def test_encrypt_as_str_and_decrypt_with_invalid_cipher_text_throws_error(
        self, did
    ):
        did.add_management_key("management-key", 1)

        password = "123456"
        encrypted_keys_cipher_b64 = did.export_encrypted_keys_as_str(password)

        with pytest.raises(ValueError):
            decrypt_keys_from_str(encrypted_keys_cipher_b64[:24], password)

    def test_encrypt_as_json_and_decrypt(self, did):
        did.add_management_key("management-key", 1)
        generated_management_key = did.management_keys[0]

        password = "123456"
        encrypted_keys_json = did.export_encrypted_keys_as_json(password)
        decrypted_keys = decrypt_keys_from_json_str(encrypted_keys_json, password)
        decrypted_management_key = decrypted_keys[0]

        assert generated_management_key.alias == decrypted_management_key["alias"]
        assert (
            generated_management_key.signature_type == decrypted_management_key["type"]
        )
        assert (
            str(generated_management_key.private_key, "utf8")
            == decrypted_management_key["privateKey"]
        )

    def test_encrypt_as_json_and_decrypt_with_invalid_password_throws_error(self, did):
        did.add_management_key("management-key", 1)

        password = "123456"
        encrypted_keys_json = did.export_encrypted_keys_as_json(password)

        invalid_password = "!23456"
        with pytest.raises(ValueError):
            decrypt_keys_from_json_str(encrypted_keys_json, invalid_password)

    def test_encrypt_as_json_and_decrypt_with_invalid_json_throws_error(self):
        invalid_json = '{"data": "KuZTmv2xmw4N+GFYNCBuqMgt8OEO24hHABPJBKjxehmqI2I0UZwzIjqf2acI8DnfYQTs0uVZxetLri"'
        password = "123qweASD!@#"
        with pytest.raises(ValueError):
            decrypt_keys_from_json_str(invalid_json, password)

    def test_encrypt_as_json_and_decrypt_with_missing_json_property_throws_error(self):
        # data property is missing from the json
        invalid_json = '{"encryptionAlgo": {"name": "AES-GCM","iv": "vLsvUFfZJ3nUe/G3GHFK1A==","salt": "GynGAsqMaVbmMviTSkx6htQpDcgL4pQ8UQRdann/Jzo=","tagLength": 128},"did": "did:fctr:3626da39a85becd84c203676bd99707723290a06ea0663d3eade8a2301910573"}'
        password = "123qweASD!@#"
        with pytest.raises(KeyError):
            decrypt_keys_from_json_str(invalid_json, password)

    def test_decrypt_keys_from_file(self):
        file_path = os.path.join(
            "tests", "fixtures", "paper-did-UTC--2019-08-06T10_51_19.432Z.txt"
        )
        password = "123qweASD!@#"
        expected_keys = [
            {
                "alias": "defaultpubkey",
                "type": "Ed25519",
                "privateKey": "AjSQe96djVuNrh2izoFrwtPFcjL5XencKRYuArbRmJpqAZtEsbJhhYYmS5KdEmCd46hjJ3fGWuRb5jeEUKgPada",
            }
        ]

        decrypted_keys = decrypt_keys_from_json_file(file_path, password)
        assert expected_keys == decrypted_keys

    def test_decrypt_keys_from_file_with_invalid_password_throws_error(self):
        file_path = os.path.join(
            "tests", "fixtures", "paper-did-UTC--2019-08-06T10_51_19.432Z.txt"
        )
        invalid_password = "qweASD!@#"
        with pytest.raises(ValueError):
            decrypt_keys_from_json_file(file_path, invalid_password)
