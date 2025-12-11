"""
Setup configuration for SaaSReady Python SDK - Production Grade
"""

from setuptools import setup, find_packages
import os

# Read long description from README
with open("README_PYPI.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read version from package
version = {}
with open("saasready/version.py", "r", encoding="utf-8") as fh:
    exec(fh.read(), version)

# Parse requirements
def parse_requirements(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

core_requirements = parse_requirements("requirements/core.txt")
postgres_requirements = parse_requirements("requirements/postgres.txt")
mysql_requirements = parse_requirements("requirements/mysql.txt")
sqlite_requirements = parse_requirements("requirements/sqlite.txt")
email_requirements = parse_requirements("requirements/email.txt")
dev_requirements = parse_requirements("requirements/dev.txt")

setup(
    name="saasready",
    version=version["__version__"],
    author="SaaSReady Team",
    author_email="hello@saasready.dev",
    description="Drop-in authentication, RBAC, and multi-tenancy for FastAPI applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/saasready",
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/saasready/issues",
        "Documentation": "https://docs.saasready.dev",
        "Source Code": "https://github.com/yourusername/saasready",
        "Changelog": "https://github.com/yourusername/saasready/releases",
        "Discord": "https://discord.gg/saasready",
    },
    packages=find_packages(exclude=["tests", "tests.*", "examples", "examples.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Framework :: FastAPI",
        "Operating System :: OS Independent",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ],
    python_requires=">=3.8",
    install_requires=core_requirements,
    extras_require={
        "postgres": postgres_requirements,
        "mysql": mysql_requirements,
        "sqlite": sqlite_requirements,
        "email": email_requirements,
        "all": core_requirements + postgres_requirements + email_requirements,
        "dev": dev_requirements,
    },
    entry_points={
        "console_scripts": [
            "saasready=saasready.cli:main",
        ],
        "fastapi.plugins": [
            "saasready=saasready:FastAPIPlugin",
        ],
    },
    include_package_data=True,
    package_data={
        "saasready": [
            "py.typed",
            "alembic/*",
            "alembic/versions/*",
            "templates/*",
            "static/*",
        ],
    },
    zip_safe=False,
    keywords=[
        "authentication",
        "authorization",
        "rbac",
        "multi-tenant",
        "fastapi",
        "saas",
        "b2b",
        "drop-in",
        "workos",
        "auth0",
        "supabase",
        "clerk",
    ],
)