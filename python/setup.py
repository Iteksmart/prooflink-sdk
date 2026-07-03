from setuptools import setup, find_packages

setup(
    name="prooflink-sdk",
    version="1.0.0",
    description="ProofLink Python SDK — EU AI Act Article 12 audit receipts",
    author="iTechSmart",
    packages=find_packages(),
    install_requires=["requests>=2.28.0"],
    python_requires=">=3.8",
)
