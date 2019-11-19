import json
from factom_did.client.constants import ENTRY_SCHEMA_V100
from factom_did.client.validators import (
    validate_alias,
    validate_priority_requirement,
    validate_service_endpoint,
)

__all__ = ["Service"]


class Service:
    """
    Represent a service associated with a DID. A service is an end-point, which can be used to communicate with the DID
    or to carry out different tasks on behalf of the DID (such as signatures, e.g.)

    Attributes
    ----------
    alias: str
        A human-readable nickname for the service endpoint.
    service_type: str
        Type of the service endpoint (e.g. email, credential store).
    endpoint: str
        A service endpoint may represent any type of service the subject wishes to advertise,
        including decentralized identity management services for further discovery,
        authentication, authorization, or interaction.
        The service endpoint must be a valid URL.
    priority_requirement: int, optional
        A non-negative integer showing the minimum hierarchical level a key must have in order to remove this service.
    custom_fields: dict, optional
        A dictionary containing custom fields (e.g "description": "My public social inbox").
    """

    def __init__(
        self,
        alias,
        service_type,
        endpoint,
        priority_requirement=None,
        custom_fields=None,
    ):
        self._validate_service_input_params(
            alias, service_type, endpoint, priority_requirement
        )

        self.alias = alias
        self.service_type = service_type
        self.endpoint = endpoint
        self.priority_requirement = priority_requirement
        self.custom_fields = custom_fields

    def __eq__(self, other):
        if self.__class__ is other.__class__:
            return (
                self.alias,
                self.service_type,
                self.endpoint,
                self.priority_requirement,
                self.custom_fields,
            ) == (
                other.alias,
                other.service_type,
                other.endpoint,
                other.priority_requirement,
                other.custom_fields,
            )
        return NotImplemented

    def __hash__(self):
        return hash(
            (
                self.alias,
                self.service_type,
                self.endpoint,
                self.priority_requirement,
                json.dumps(self.custom_fields) if self.custom_fields else None,
            )
        )

    def __repr__(self):
        return "<{}.{}(alias={}, service_type={}, endpoint={}, priority_requirement={}, custom_fields={})>".format(
            self.__module__,
            type(self).__name__,
            self.alias,
            self.service_type,
            self.endpoint,
            self.priority_requirement,
            self.custom_fields,
        )

    def to_entry_dict(self, did, version=ENTRY_SCHEMA_V100):
        """
        Converts the object to a dictionary suitable for recording on-chain.

        Parameters
        ----------
        did: str
            The DID to which this service belongs.
        version: str
            The entry schema version

        Raises
        ------
        NotImplementedError
            If the entry schema version is not supported
        """
        if version == ENTRY_SCHEMA_V100:
            d = dict()

            d["id"] = self.full_id(did)
            d["type"] = self.service_type
            d["serviceEndpoint"] = self.endpoint
            if self.priority_requirement is not None:
                d["priorityRequirement"] = self.priority_requirement

            if self.custom_fields is not None:
                for key in self.custom_fields:
                    d[key] = self.custom_fields[key]

            return d
        else:
            raise NotImplementedError("Unknown schema version: {}".format(version))

    @staticmethod
    def from_entry_dict(entry_dict, version=ENTRY_SCHEMA_V100):
        if version == ENTRY_SCHEMA_V100:
            custom_fields = dict()
            for key in entry_dict:
                if key not in ("id", "type", "serviceEndpoint", "priorityRequirement"):
                    custom_fields[key] = entry_dict[key]

            return Service(
                alias=entry_dict.get("id", "").split("#")[-1],
                service_type=entry_dict.get("type", ""),
                endpoint=entry_dict.get("serviceEndpoint", ""),
                priority_requirement=entry_dict.get("priorityRequirement"),
                custom_fields=custom_fields if len(custom_fields.items()) > 0 else None,
            )
        else:
            raise NotImplementedError("Unknown schema version: {}".format(version))

    def full_id(self, did):
        """
        Returns
        -------
        str
            The full id for the service, constituting of the DID_METHOD_NAME, the controller and the service alias.
        """
        return "{}#{}".format(did, self.alias)

    @staticmethod
    def _validate_service_input_params(
        alias, service_type, endpoint, priority_requirement
    ):
        validate_alias(alias)

        if not service_type:
            raise ValueError("Type is required.")

        validate_service_endpoint(endpoint)
        validate_priority_requirement(priority_requirement)
