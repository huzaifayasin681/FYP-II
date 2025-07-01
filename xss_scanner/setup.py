# setup.py
"""Setup configuration for XSS Scanner."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

# Read requirements
requirements = (this_directory / "requirements.txt").read_text().splitlines()

setup(
    name="xss-scanner",
    version="1.0.0",
    author="XSS Scanner Team",
    author_email="team@xss-scanner.com",
    description="Production-grade XSS vulnerability scanning framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/xss-scanner/xss-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.20.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.990",
        ]
    },
    entry_points={
        "console_scripts": [
            "xss-scanner=xss_scanner.cli.main:main",
            "xss-scanner-gui=xss_scanner.gui.app:main",
        ],
    },
    package_data={
        "xss_scanner": ["payloads/*.txt"],
    },
    include_package_data=True,
)