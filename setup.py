"""Setup script for AD Group Audit."""

from setuptools import setup, find_packages

from ad_group_audit.version import __author__, __version__

setup(
    name="ad-group-audit",
    version=__version__,
    author=__author__,
    description="Active Directory group membership auditing tool",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "ldap3",
        "pyodbc",
    ],
    extras_require={
        "dev": [
            "pytest",
            "hypothesis",
            "pyinstaller",
        ],
    },
    entry_points={
        "console_scripts": [
            "ad-group-audit=ad_group_audit.main:main",
        ],
    },
)
