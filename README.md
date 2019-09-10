# py-factom-did

py-factom-did is a Python library, allowing the creation of a Decentralized Identifier (DID) and
the exporting of the public metadata for it, which can be recorded on the Factom blockchain.
The library enables:

* creating a new DID
* adding management key(s) for the DID
* adding DID key(s) for the DID
* adding service(s) for the DID
* exporting public metadata to be recorded on Factom
* encrypting the newly created keys

You can find an example of the library workflow in the `examples/` directory. In order to run the
example, please note that it is necessary to create an environment variable called `EC_ADDR`, which
contains a funded EC address to pay the fees for recording the DID on-chain.

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
