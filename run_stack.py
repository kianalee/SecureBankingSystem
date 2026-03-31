"""Launch the bank server and web surface together for local development."""

from __future__ import annotations

import argparse
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Tuple

from secure_banking.config import (
    get_frontend_dev_host,
    get_frontend_dev_port,
    get_gateway_host,
    get_gateway_port,
    get_project_root,
)


def build_commands(frontend_dev: bool) -> List[Tuple[str, List[str], Path]]:
    project_root = get_project_root()
    commands: List[Tuple[str, List[str], Path]] = [
        ("bank-server", [sys.executable, "BankServer.py"], project_root),
        (
            "gateway",
            [
                sys.executable,
                "-m",
                "uvicorn",
                "secure_banking.gateway:app",
                "--host",
                get_gateway_host(),
                "--port",
                str(get_gateway_port()),
            ],
            project_root,
        ),
    ]

    if frontend_dev:
        npm = shutil.which("npm")
        if npm is None:
            raise RuntimeError("npm is required to run the frontend dev server.")

        commands.append(
            (
                "frontend",
                [
                    npm,
                    "run",
                    "dev",
                    "--",
                    "--host",
                    get_frontend_dev_host(),
                    "--port",
                    str(get_frontend_dev_port()),
                ],
                project_root / "frontend",
            )
        )

    return commands


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the SecureBankingSystem stack.")
    parser.add_argument(
        "--frontend-dev",
        action="store_true",
        help="Start the Vite dev server instead of relying on frontend/dist.",
    )
    args = parser.parse_args()

    processes: List[Tuple[str, subprocess.Popen[str]]] = []

    def shutdown(*_: object) -> None:
        for _, process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for _, process in reversed(processes):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        for name, command, cwd in build_commands(args.frontend_dev):
            print("[launch] {} -> {}".format(name, " ".join(command)))
            process = subprocess.Popen(command, cwd=cwd)
            processes.append((name, process))
            time.sleep(0.8)

        if args.frontend_dev:
            print("[ready] Web UI: http://{}:{}".format(get_frontend_dev_host(), get_frontend_dev_port()))
        else:
            print("[ready] Web UI: http://{}:{}".format(get_gateway_host(), get_gateway_port()))

        print("[ready] Press Ctrl+C to stop all services.")

        while True:
            for name, process in processes:
                code = process.poll()
                if code is not None:
                    print("[exit] {} exited with code {}".format(name, code))
                    shutdown()
                    return code
            time.sleep(1)
    finally:
        shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
