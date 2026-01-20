"""
SaaSReady Python SDK Setup
Enterprise authentication and multi-tenancy for Python applications
"""
from setuptools import setup, find_packages
import os

# Read the README file
with open("SDK_README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
def read_requirements(filename):
    """Read requirements from file"""
    with open(filename, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

# Core dependencies
install_requires = [
    "requests>=2.25.0,<3.0.0",
    "pydantic>=2.0.0,<3.0.0",
    "python-dateutil>=2.8.0,<3.0.0",
]

# Development dependencies
dev_requires = [
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
    "pytest-mock>=3.10.0",
    "black>=23.0.0",
    "flake8>=6.0.0",
    "mypy>=1.0.0",
    "isort>=5.12.0",
    "pre-commit>=3.0.0",
    "tox>=4.0.0",
    "build>=0.10.0",
    "twine>=4.0.0",
    "wheel>=0.40.0",
    "responses>=0.23.0",
    "faker>=18.0.0",
]

# Documentation dependencies
docs_requires = [
    "sphinx>=6.0.0",
    "sphinx-rtd-theme>=1.2.0",
    "sphinx-autodoc-typehints>=1.22.0",
]

# Async support dependencies
async_requires = [
    "httpx>=0.24.0",
    "aiohttp>=3.8.0",
]

setup(
    name="saasready",
    version="1.0.0",
    author="SaaSReady Team",
    author_email="support@saasready.com",
    description="Enterprise-grade authentication and multi-tenancy SDK for Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ramprag/saasready",
    project_urls={
        "Documentation": "https://docs.saasready.com",
        "Bug Reports": "https://github.com/ramprag/saasready/issues",
        "Source": "https://github.com/ramprag/saasready",
        "Changelog": "https://github.com/ramprag/saasready/blob/main/CHANGELOG.md",
    },
    packages=find_packages(exclude=["tests", "tests.*", "docs", "examples"]),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ],
    python_requires=">=3.8",
    install_requires=install_requires,
    extras_require={
        "dev": dev_requires,
        "docs": docs_requires,
        "async": async_requires,
        "all": dev_requires + docs_requires + async_requires,
    },
    include_package_data=True,
    package_data={
        "saasready": ["py.typed"],
    },
    zip_safe=False,
    keywords=[
        "authentication",
        "authorization",
        "saas",
        "multi-tenancy",
        "rbac",
        "jwt",
        "oauth",
        "identity",
        "access-control",
        "enterprise-auth",
    ],
)
