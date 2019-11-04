#!/usr/bin/env python

from setuptools import setup, find_packages


with open("README.md", "r") as fh:
    long_description = fh.read()

CLASSIFIERS = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Topic :: Internet :: WWW/HTTP",
    "Topic :: Security",
    "Topic :: Security :: Cryptography",
    "Topic :: Software Development",
]


setup(
    author="Peter Asenov, Valentin Ganev",
    author_email="info@factomatic.io",
    name="py-factom-did",
    version="0.5.0",
    description="Python library for Factom DIDs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT License",
    platforms=["OS Independent"],
    classifiers=CLASSIFIERS,
    packages=find_packages(exclude=["tests"]),
    include_package_data=True,
    install_requires=[
        "base58>=1.0.3",
        "ecdsa>=0.13.2",
        "ed25519>=1.5",
        "factom-api>=1.0.2",
        "pycryptodome>=3.9.0",
    ],
    url="https://github.com/factomatic/py-factom-did",
    python_requires=">=3.6",
)
