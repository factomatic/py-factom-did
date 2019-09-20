from os.path import abspath, dirname, join

import jsonref
from jsonschema.validators import validator_for


def load_json_schema(filename, version):
    """Loads the given schema file"""

    relative_path = join("resolver", "schemas", version, filename)
    absolute_path = abspath(relative_path)

    base_path = dirname(absolute_path)
    base_uri = "file://{}/".format(base_path)

    with open(absolute_path) as schema_file:
        return jsonref.loads(schema_file.read(), base_uri=base_uri, jsonschema=True)


def get_schema_validator(schema_file, version="1.0.0"):
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
    schema = load_json_schema(schema_file, version)
    cls = validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)
