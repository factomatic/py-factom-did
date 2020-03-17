import pytest

from factom_did.client.did import DID
from factom_did.client.service import Service


@pytest.fixture
def did():
    return DID()


class TestService:
    def test_add_service(self, did):
        service_1_alias = "photo-service"
        service_1_type = "PhotoStreamService"
        service_1_endpoint = "https://myphoto.com"
        did.service(service_1_alias, service_1_type, service_1_endpoint)
        generated_service_1 = did.services[0]

        assert service_1_alias == generated_service_1.alias
        assert service_1_type == generated_service_1.service_type
        assert service_1_endpoint == generated_service_1.endpoint
        assert generated_service_1.priority_requirement is None
        assert generated_service_1.custom_fields is None

        service_2_alias = "auth-service"
        service_2_type = "AuthenticationService"
        service_2_endpoint = "https://authenticateme.com"
        service_2_priority_requirement = 2
        did.service(
            service_2_alias,
            service_2_type,
            service_2_endpoint,
            service_2_priority_requirement,
        )
        generated_service_2 = did.services[1]

        assert service_2_alias == generated_service_2.alias
        assert service_2_type == generated_service_2.service_type
        assert service_2_endpoint == generated_service_2.endpoint
        assert generated_service_2.custom_fields is None
        assert (
            service_2_priority_requirement == generated_service_2.priority_requirement
        )

        service_3_alias = "inbox"
        service_3_type = "SocialWebInboxService"
        service_3_endpoint = "https://social.example.com/83hfh37dj"
        service_3_priority_requirement = 3
        service_3_custom_fields = {
            "description": "My public social inbox",
            "spamCost": {"amount": "0.50", "currency": "USD"},
        }
        did.service(
            service_3_alias,
            service_3_type,
            service_3_endpoint,
            service_3_priority_requirement,
            service_3_custom_fields,
        )
        generated_service_3 = did.services[2]

        assert service_3_alias == generated_service_3.alias
        assert service_3_type == generated_service_3.service_type
        assert service_3_endpoint == generated_service_3.endpoint
        assert service_3_custom_fields == generated_service_3.custom_fields
        assert (
            service_3_priority_requirement == generated_service_3.priority_requirement
        )

        assert 3 == len(did.services)

    def test_invalid_alias_throws_exception(self, did):
        service_type = "PhotoStreamService"
        service_endpoint = "https://myphoto.com"
        test_cases = ["myPhotoService", "my-ph@to-service", "my_photo_service"]
        for alias in test_cases:
            with pytest.raises(ValueError):
                did.service(alias, service_type, service_endpoint)

    def test_used_alias_throws_exception(self, did):
        service_alias = "my-photo-service"
        service_type = "PhotoStreamService"
        service_endpoint = "https://myphoto.com"
        did.service(service_alias, service_type, service_endpoint)
        with pytest.raises(ValueError):
            did.service(service_alias, service_type, service_endpoint)

    def test_empty_service_type_throws_exception(self, did):
        service_alias = "my-photo-service"
        service_type = ""
        service_endpoint = "https://myphoto.com"
        with pytest.raises(ValueError):
            did.service(service_alias, service_type, service_endpoint)

    def test_invalid_endpoint_throws_exception(self, did):
        service_type = "PhotoStreamService"
        test_cases = [
            ("service-1", "myservice.com"),
            ("service-2", "https//myphoto.com"),
        ]

        for alias, endpoint in test_cases:
            with pytest.raises(ValueError):
                did.service(alias, service_type, endpoint)

    def test_invalid_priority_requirement_throws_exception(self, did):
        service_type = "PhotoStreamService"
        service_endpoint = "https://myphoto.com"
        test_cases = [-1, -2, 1.5, "one"]
        for priority_requirement in test_cases:
            service_alias = "service-{}".format(str(priority_requirement))
            with pytest.raises(ValueError):
                did.service(
                    service_alias, service_type, service_endpoint, priority_requirement
                )

    def test__repr__method(self, did):
        service_alias = "photo-service"
        service_type = "PhotoStreamService"
        service_endpoint = "https://myphoto.com"
        service_priority_requirement = 1
        service_custom_fields = {"description": "A photo stream service"}
        did.service(
            service_alias,
            service_type,
            service_endpoint,
            service_priority_requirement,
            service_custom_fields,
        )
        generated_service = did.services[0]

        expected__repr__method_output = (
            "<{}.{}(alias={}, service_type={}, "
            "endpoint={}, priority_requirement={}, custom_fields={})>".format(
                Service.__module__,
                Service.__name__,
                service_alias,
                service_type,
                service_endpoint,
                service_priority_requirement,
                service_custom_fields,
            )
        )

        assert str(generated_service) == expected__repr__method_output
