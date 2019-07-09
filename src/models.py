from collections import namedtuple

__all__ = ['KeyPairModel', 'KeyModel', 'ServiceModel']

KeyPairModel = namedtuple('KeyPairModel', ('public_key', 'private_key'))

KeyModel = namedtuple('KeyModel', ('alias', 'signature_type', 'controller', 'public_key', 'private_key'),
                      defaults=(None,))

ServiceModel = namedtuple('ServiceModel', ('service_type', 'endpoint', 'alias'))
