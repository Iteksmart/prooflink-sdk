from pathlib import Path
from setuptools import setup, find_packages

ROOT = Path(__file__).resolve().parent.parent
long_description = (ROOT / 'README.md').read_text(encoding='utf-8') if (ROOT / 'README.md').exists() else ''

setup(
    name='prooflink',
    version='0.1.0',
    description='Cryptographic receipt SDK for autonomous AI actions',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='iTechSmart Inc.',
    author_email='djuane@itechsmart.dev',
    url='https://github.com/Iteksmart/prooflink-sdk',
    license='MIT',
    packages=find_packages(),
    install_requires=['requests>=2.25'],
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
)
