"""
main.py  -  Cyber Threat Log Analyzer (Day 1: setup check)
==========================================================
Today this file only verifies that your setup is correct:
    1. Python version is new enough
    2. Required libraries are installed
    3. The synthetic datasets exist and contain the expected columns

On Day 6 this file will become the full menu-driven terminal application.

Run from the project root folder:
    python main.py
"""

import importlib
import sys

from src import config

LINE = "=" * 60


def print_banner():
    """Show the project title."""
    print(LINE)
    print("   CYBER THREAT LOG ANALYZER  -  Day 1 Setup Check")
    print("   All datasets used here are SYNTHETIC (fake) data")
    print(LINE)


def print_status(ok, label, detail=""):
    """Print one check result such as:  [ OK ] Python version : 3.12.1"""
    tag = "[ OK ]" if ok else "[FAIL]"
    print(f"{tag} {label:<22}: {detail}")


def check_python_version(minimum=(3, 8)):
    """Return True if the running Python is at least `minimum`."""
    current = sys.version_info[:3]
    ok = current >= minimum
    print_status(ok, "Python version", ".".join(str(n) for n in current))
    return ok


def check_libraries():
    """Try to import every required library and show its version."""
    all_ok = True
    for name in ["pandas", "numpy", "matplotlib"]:
        try:
            module = importlib.import_module(name)
            print_status(True, f"Library {name}", module.__version__)
        except ImportError:
            print_status(False, f"Library {name}",
                         "not installed -> run: pip install -r requirements.txt")
            all_ok = False
    return all_ok


def check_dataset(file_path, expected_columns):
    """Load one CSV with pandas and validate it. Returns True if it looks good."""
    import pandas as pd   # imported here so a missing pandas gives a clear message above

    name = file_path.name
    if not file_path.exists():
        print_status(False, name, "file not found - run scripts/generate_sample_data.py")
        return False

    try:
        df = pd.read_csv(file_path)
    except Exception as error:               # corrupted or unreadable file
        print_status(False, name, f"could not be read ({error})")
        return False

    missing = [col for col in expected_columns if col not in df.columns]
    if missing:
        print_status(False, name, f"missing columns: {missing}")
        return False

    print_status(True, name,
                 f"{len(df)} rows, {df['ip_address'].nunique()} unique IPs")
    print(f"{'':<30}time range: {df['timestamp'].min()}  ->  {df['timestamp'].max()}")
    return True


def main():
    print_banner()

    results = []
    results.append(check_python_version())
    results.append(check_libraries())

    # Only check datasets if the libraries are available
    if results[-1]:
        print()
        results.append(check_dataset(config.DEFAULT_ACCESS_LOG, config.ACCESS_LOG_COLUMNS))
        results.append(check_dataset(config.DEFAULT_AUTH_LOG, config.AUTH_LOG_COLUMNS))

    print(LINE)
    if all(results):
        print("Day 1 setup complete. You are ready for Day 2 (log loading & parsing).")
    else:
        print("Some checks failed. Fix the [FAIL] lines above and run again.")
    print(LINE)


if __name__ == "__main__":
    main()
