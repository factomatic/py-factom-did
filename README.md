[![Build Status](https://travis-ci.org/factomatic/py-factom-did.svg?branch=master)](https://travis-ci.org/factomatic/py-factom-did)
[![Coverage Status](https://coveralls.io/repos/github/factomatic/py-factom-did/badge.svg?branch=master)](https://coveralls.io/github/factomatic/py-factom-did?branch=master)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)

# py-factom-did

`py-factom-did` is a Python library for working with DIDs on the Factom blockchain. It is an implementation
of the [Factom DID method
specification](https://github.com/bi-foundation/FIS/blob/feature/DID/FIS/DID.md) and consists of two main modules:
`factom_did.client` and `factom_did.resolver`.

The `client` module enables:

* creation of a new DID
* addition of management key(s) for the DID
* addition of DID key(s) for the DID
* addition of service(s) for the DID
* export of public metadata to be recorded on Factom
* encryption of the newly created keys
* update of an existing DID: adding/revoking management keys, DID keys and services and producing a signed DID
update entry
* upgrade of the method version of an existing DID
* deactivaiton of an existing DID

The `resolver` module contains a pure-data library for re-constructing the effective DID Document from a list of DID
entries. It is a complete implementation of the resolver specification in https://github.com/bi-foundation/FIS/blob/feature/DID/FIS/DID.md
and contains an extensive unit test suite with 100% test coverage.

## Examples
You can find an example of the library workflow in the `examples/` directory. In order to run the
example, please note that it is necessary to:

* have local instances of `factomd` and `factom-walletd` running
* create an environment variable called `EC_ADDR`, which contains a funded EC
address to pay the fees for recording the DID on-chain

## Installation
```
pip install py-factom-did
```

## Documentation
API documentation of the library is available [here](https://py-factom-did.readthedocs.io/en/stable/)

## Build

* Clone the repo

* Create the virtual environment and install the dependencies:
```
pipenv install
```

or
```
pipenv install --pre -d
```
to install both the default and development dependencies

* Activate the virtual environment:
```
pipenv shell
```

* Execute the tests:
```
pytest
```

* Execute the example:
```
python -m examples.example
```
