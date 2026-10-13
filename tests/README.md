# GUI smoke tests

Drive the real Tk window headlessly (dialogs are stubbed) against a real or
fake nmap. They need a display, so they are run by hand, not in CI:

    python3 tests/gui_smoke.py       # scan localhost, stop a scan, quit mid-scan
    python3 tests/gui_partial.py     # Stop keeps the finished hosts (fake nmap)
    python3 tests/gui_features.py    # history, compare, HTML export, settings, support bundle

Each writes into a temporary folder and prints `... OK` on success. The unit
tests are `python3 test_modules.py` at the repository root.
