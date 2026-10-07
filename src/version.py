"""
Single source of truth for the scanner's version.

Read by the CLI, the GUI, the report writers, and the Windows installer
build, so a release is one edit here.
"""

__version__ = "1.1.0"


if __name__ == "__main__":
    # The Windows build script reads the version by running this file.
    print(__version__)
