from os.path import abspath, dirname, join

from factom_did.client.constants import ENTRY_SCHEMA_V100

import jsonref
from jsonschema.validators import validator_for


def _load_json_schema(filename, version=ENTRY_SCHEMA_V100):
    """Loads the given schema file"""

    relative_path = join("factom_did", "resolver", "schemas", version, filename)
    absolute_path = abspath(relative_path)

    base_path = dirname(absolute_path)
    base_uri = "file://{}/".format(base_path)

    with open(absolute_path) as schema_file:
        return jsonref.loads(schema_file.read(), base_uri=base_uri, jsonschema=True)


def get_schema_validator(schema_file, version=ENTRY_SCHEMA_V100):
    """Instantiates the jsonschema.Validator instance for the given schema and version

    Parameters
    ----------
    schema_file: str
        The filename of the JSON schema
    version: str, optional
        The version of the schema

    Returns
    -------
    jsonschema.Validator
        The validator instance for the given schema and version
    """
    schema = _load_json_schema(schema_file, version)
    cls = validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)
