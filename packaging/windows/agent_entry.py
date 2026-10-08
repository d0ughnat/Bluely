"""Frozen Windows agent entry point and isolated SQLite packaging self-test."""

import sys


def sqlite_self_test() -> None:
    import _sqlite3  # noqa: F401 - verify the native extension is loadable.
    import sqlite3

    with sqlite3.connect(":memory:") as database:
        database.execute("CREATE TABLE packaging_test (value TEXT NOT NULL)")
        database.execute("INSERT INTO packaging_test (value) VALUES (?)", ("sqlite-ok",))
        value = database.execute("SELECT value FROM packaging_test").fetchone()[0]
    if value != "sqlite-ok":
        raise RuntimeError("Frozen SQLite readback did not match")

if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        try:
            sqlite_self_test()
        except Exception as error:
            if sys.stderr is not None:
                print(f"Bluely SQLite self-test failed: {error}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    from blueguard.cli import main
    main()
