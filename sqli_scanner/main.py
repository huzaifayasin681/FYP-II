#!/usr/bin/env python3
"""
main.py  – Entry point for the SQLi Scanner CLI
"""

import urllib3
# Suppress “Unverified HTTPS request” warnings if verify=False is used
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from cli import app

if __name__ == "__main__":
    app()
