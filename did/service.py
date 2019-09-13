import re

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
    priority_requirement: int or None
        A non-negative integer showing the minimum hierarchical level a key must have in order to remove this service.
    """

    def __init__(self, alias, service_type, endpoint, priority_requirement):
        self._validate_service_input_params(
            alias, service_type, endpoint, priority_requirement
        )

        self.alias = alias
        self.service_type = service_type
        self.endpoint = endpoint
        self.priority_requirement = priority_requirement

    @staticmethod
    def _validate_service_input_params(
        alias, service_type, endpoint, priority_requirement
    ):
        if not re.match("^[a-z0-9-]{1,32}$", alias):
            raise ValueError(
                "Alias must not be more than 32 characters long and must contain only lower-case "
                "letters, digits and hyphens."
            )

        if not service_type:
            raise ValueError("Type is required.")

        if not re.match(
            r"^(http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?$",
            endpoint,
        ):
            raise ValueError(
                "Endpoint must be a valid URL address starting with http:// or https://."
            )

        if priority_requirement is not None and priority_requirement < 0:
            raise ValueError("Priority requirement must be a non-negative integer.")