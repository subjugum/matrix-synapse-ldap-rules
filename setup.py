from setuptools import setup
import ldap_rules


setup(
    name="ldap_rules",
    url="https://github.com/subjugum/matrix-synapse-ldap-rules",
    version=ldap_rules.__version__,
    author="Johannes H.",
    description="Synapse module for various rules depending on LDAP attributes.",
    py_modules=["ldap_rules"],
    classifiers=[
        "Development Status :: 1 - Alpha",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3 :: Only"
    ],
    include_package_data=True,
    zip_safe=True,
    install_requires=[
        "Twisted>=15.1.0",
        "ldap3>=2.8",
        "service_identity",
    ],
)
