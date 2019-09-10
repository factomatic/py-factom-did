from collections import namedtuple

__all__ = ["KeyPairModel", "ManagementKeyModel", "DidKeyModel", "ServiceModel"]

KeyPairModel = namedtuple("KeyPairModel", ("public_key", "private_key"))

ManagementKeyModel = namedtuple(
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

DidKeyModel = namedtuple(
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

ServiceModel = namedtuple(
    "ServiceModel", ("alias", "service_type", "endpoint", "priority_requirement")
)
