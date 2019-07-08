__all__ = ['KeyPairModel', 'KeyModel', 'ServiceModel']


class KeyPairModel:
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key


class KeyModel:
    def __init__(self, alias, signature_type, controller, public_key, private_key=None):
        self.alias = alias
        self.signature_type = signature_type
        self.controller = controller
        self.public_key = public_key
        self.private_key = private_key


class ServiceModel:
    def __init__(self, service_type, endpoint, alias):
        self.service_type = service_type
        self.endpoint = endpoint
        self.alias = alias
