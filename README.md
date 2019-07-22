# py-factom-did

py-factom-did is a Python library, allowing you to create a Decentralized Identifier (DID) and
export the public metadata for it, which can be recorded on Factom blockchain. The library provides the following functionality:

* creating a new DID
* adding management key(s) for the DID
* adding did key(s) for the DID
* adding service(s) for the DID
* exporting public metadata to be recorded on Factom
* encrypting the newly created keys

You can find an example of the library workflow in the src/examples directory.

## Build

* Clone the repo

* Create virtual environment and install the dependencies
```
	pipenv install
```

* Move to src directory
```
	pipenv shell
	cd src
```

* Execute the tests with
```
	python test.py
```

* Execute the example
```
	python -m examples.example
```