from setuptools import setup, find_packages

setup(
    name="advcsv",
    version="0.1.1",
    packages=find_packages(),
    install_requires=["cryptography", "jsonschema"],
    author="Sumedh Patil",
    author_email="admin@aipresso.uk",
    description="Advanced CSV handling with encryption, compression, and validation.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Sumedh1599/advcsv",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
