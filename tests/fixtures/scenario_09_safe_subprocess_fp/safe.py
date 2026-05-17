# NOT vulnerable: subprocess with shell=False and a literal argument list.
# Some Semgrep rules still match subprocess.run() as "potentially dangerous";
# our exploitability agent should downgrade or mark this as false-positive.
# CWE: none (this is the secure pattern).

import subprocess


def list_directory(path: str) -> list[str]:
    # No shell expansion. `path` is passed as a single argv element, so
    # it cannot turn into an injection vector. Path-traversal is a
    # separate concern from command injection.
    result = subprocess.run(
        ["ls", "-la", path],
        shell=False,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.splitlines()
