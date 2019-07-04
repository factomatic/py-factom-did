__all__ = ['KeyPairModel', 'KeyModel', 'ServiceModel']


class KeyPairModel:
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key


class KeyModel:
    def __init__(self, alias, type, controller, public_key, private_key=None):
        self.alias = alias
        self.type = type
        self.controller = controller
        self.public_key = public_key
        self.private_key = private_key


class ServiceModel:
    def __init__(self, type, endpoint, alias):
        self.type = type
        self.endpoint = endpoint
        self.alias = alias
