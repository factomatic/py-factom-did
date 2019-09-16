[![Build Status](https://travis-ci.org/factomatic/py-factom-did.svg?branch=master)](https://travis-ci.org/factomatic/py-factom-did)
[![Coverage Status](https://coveralls.io/repos/github/factomatic/py-factom-did/badge.svg?branch=master)](https://coveralls.io/github/factomatic/py-factom-did?branch=master)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)

# py-factom-did

py-factom-did is a Python library, allowing the creation and update of Decentralized Identifiers (DIDs) and
the exporting of public metadata for them, which can be recorded on the Factom blockchain.
The library enables:

* creating a new DID
* adding management key(s) for the DID
* adding DID key(s) for the DID
* adding service(s) for the DID
* exporting public metadata to be recorded on Factom
* encrypting the newly created keys
* updating an existing DID: adding/revoking management keys, DID keys and services and producing a signed DID
update entry

You can find an example of the library workflow in the `examples/` directory. In order to run the
example, please note that it is necessary to:

* have local instances of `factomd` and `factom-walletd` running
* create an environment variable called `EC_ADDR`, which contains a funded EC
address to pay the fees for recording the DID on-chain

## Installation
```
pip install py-factom-did
```

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

## Documentation
API documentation of the library is available [here](https://py-factom-did.readthedocs.io/en/stable/)
