import re

from factom_did.client.constants import DID_METHOD_NAME
from factom_did.client.enums import KeyType, Network


def validate_alias(alias):
    if not re.match("^[a-z0-9-]{1,32}$", alias):
        raise ValueError(
            "Alias must not be more than 32 characters long and must contain only lower-case "
            "letters, digits and hyphens."
        )


def validate_did(did):
    if not re.match(
        "^{}:({}:|{}:)?[a-f0-9]{{64}}$".format(
            DID_METHOD_NAME, Network.Mainnet.value, Network.Testnet.value
        ),
        did,
    ):
        raise ValueError("Controller must be a valid DID.")


def validate_full_key_identifier(did):
    if not re.match(
        "^{}:({}:|{}:)?[a-f0-9]{{64}}#[a-zA-Z0-9-]{{1,32}}$".format(
            DID_METHOD_NAME, Network.Mainnet.value, Network.Testnet.value
        ),
        did,
    ):
        raise ValueError("Controller must be a valid DID.")


def validate_service_endpoint(endpoint):
    if not re.match(
        r"^(http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?$",
        endpoint,
    ):
        raise ValueError(
            "Endpoint must be a valid URL address starting with http:// or https://."
        )


def validate_priority_requirement(priority_requirement):
    if priority_requirement is not None and priority_requirement < 0:
        raise ValueError("Priority requirement must be a non-negative integer.")


def validate_key_type(key_type):
    if key_type not in (KeyType.ECDSA, KeyType.EdDSA, KeyType.RSA):
        raise ValueError("Type must be a valid signature type.")
