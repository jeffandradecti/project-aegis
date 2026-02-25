from setuptools import setup, find_packages

setup(
    name="panoptik",
    version="0.1.0",
    description="A modular malware triage and analysis orchestrator",
    author="Jefferson Andrade",
    packages=find_packages(),
    install_requires=[
        "pefile",
        "python-magic",
        "capstone",
        "iocextract",
        "validators",
        "boto3"
    ],
    entry_points={
        "console_scripts": [
            "panoptik=panoptik_cli:main",
        ],
    },
    python_requires=">=3.8",
)
