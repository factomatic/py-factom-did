from collections import namedtuple

__all__ = ["KeyPair", "ManagementKey", "DidKey", "Service"]

KeyPair = namedtuple("KeyPair", ("public_key", "private_key"))

ManagementKey = namedtuple(
    "ManagementKeyModel",
    (
        "alias",
        "priority",
        "signature_type",
        "controller",
        "public_key",
        "private_key",
        "priority_requirement",
    ),
)

DidKey = namedtuple(
    "DidKeyModel",
    (
        "alias",
        "purpose",
        "signature_type",
        "controller",
        "public_key",
        "private_key",
        "priority_requirement",
    ),
)

Service = namedtuple(
    "ServiceModel", ("alias", "service_type", "endpoint", "priority_requirement")
)
