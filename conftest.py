"""
conftest.py

Ensures the repo root is on sys.path for every test file pytest collects,
regardless of which directory pytest is invoked from, which invocation
style is used (bare `pytest`, `python -m pytest`, an IDE's test runner,
etc.), or whether an individual test file remembers its own sys.path
bootstrap.

This is the standard pytest mechanism for making a project's own local
packages (shared/, storage/, parsers/, detector/, etc.) importable during
tests without installing the project as a package first. pytest
automatically discovers and loads a root-level conftest.py before
collecting any test files, which makes this the most reliable place to
fix path resolution for the whole test suite in one shot.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))