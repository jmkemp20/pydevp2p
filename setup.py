from setuptools import setup, find_packages, find_namespace_packages

with open("requirements.txt") as file:
    reqs = file.read().splitlines()

namespace_pkgs = find_namespace_packages()
pkgs = find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"])
pkgs = namespace_pkgs + pkgs


setup(
    name='pydevp2p',
    version='0.1.0',
    description="A Toolkit Helper Library for Ethereum ECIES and Devp2p",
    url='https://github.com/jmkemp20/pydevp2p',
    author='Joshua Kemp',
    author_email="kem3jm@dukes.jmu.edu",
    license='MIT License',
    setup_requires=['setuptools==59.6.0', 'wheel'],
    packages=pkgs,
    include_package_data=True,
    zip_safe=False,
    install_requires=reqs,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3 :: Only",
    ],
    keywords="devp2p, ethereum, ecies, ecc, ecdh, ecdsa, rlp, rlpx",
    python_requires=">=3.7, <4",
)
