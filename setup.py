# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="vaultra",
    version="0.1.0",
    author="Jerly Rojas",
    author_email="hello@vaultra.io",
    description="AI Agent Compliance Layer — Immutable audit trail for AI decisions in regulated industries",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jerlyrojas/vaultra",
    project_urls={
        "Website": "https://vaultra.io",
        "Bug Reports": "https://github.com/jerlyrojas/vaultra/issues",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Office/Business :: Financial",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    install_requires=[
        "cryptography>=41.0.0",
        "scikit-learn>=1.3.0",
        "numpy>=1.24.0",
    ],
    keywords="ai-security compliance audit-trail ai-agents gdpr eu-ai-act fintech",
)
