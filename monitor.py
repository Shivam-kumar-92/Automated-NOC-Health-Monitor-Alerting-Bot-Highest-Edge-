#!/usr/bin/env python3
"""Entry point for the Automated NOC Health Monitor & Alerting Bot."""

import sys

from noc_monitor.cli import main

if __name__ == "__main__":
    sys.exit(main())
