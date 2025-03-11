"""
Unit Test Script to Run Multiple Commands Concurrently
======================================================

This script reads a list of commands from a file and executes them concurrently in separate subprocesses.
Each command is run in a Zsh shell with a set timeout.
The script logs the standard output and standard error of each command to separate log files based on the outcome of the command (success, failure, or timeout).

Run this script using an asyncio capable Python interpreter (Python 3.7+ recommended).
This script requires `asyncio` and `tempfile` libraries.

Author: Shutdown
"""

import asyncio
import tempfile
import subprocess
from concurrent.futures import TimeoutError as FuturesTimeoutError

# File paths for command input and logging
COMMANDS_FILE = "/.exegol/build_pipeline_tests/all_commands.txt"
FAIL_LOG_FILE = "/.exegol/build_pipeline_tests/failed_commands.log"
TIMEOUT_LOG_FILE = "/.exegol/build_pipeline_tests/timedout_commands.log"
SUCCESS_LOG_FILE = "/.exegol/build_pipeline_tests/success_commands.log"

# ANSI Color Codes for colored output
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[33m"
RESET = "\033[0m"

# Configuration constants
COMMAND_TIMEOUT = 30
CONCURRENT_TASKS = 5

class CommandRunner:
    def __init__(self, parallel_tasks: int = 20):
        # Semaphore to limit the number of concurrent tasks
        self.sem = asyncio.Semaphore(parallel_tasks)
        # Lists to store commands that failed or timed out
        self.failed_commands = []
        self.timedout_commands = []

    async def run(self, commands: list[str]) -> None:
        # Running all commands concurrently
        await asyncio.gather(*(self._run_command(command) for command in commands))

    async def _run_command(self, command: str) -> None:
        async with self.sem:
            # Using a temporary file to store and run the command
            with tempfile.NamedTemporaryFile(mode='w') as temp:
                temp.write(command)
                temp.flush()
                # Constructing the command to run in a Zsh shell
                zsh_command = f"zsh -c 'autoload -Uz compinit; compinit; source ~/.zshrc; . {temp.name}'"
                loop = asyncio.get_running_loop()
                try:
                    # Running the command as a subprocess and capturing the output
                    proc, stdout, stderr = await loop.run_in_executor(None, self._run_subprocess, zsh_command, COMMAND_TIMEOUT)
                    if proc.returncode == 0:
                        print(f"{GREEN}SUCCESS{RESET} - Running command: {command}")
                        self._log_command(log_file=SUCCESS_LOG_FILE, command=command, stdout=stdout, stderr=stderr)
                    else:
                        self.failed_commands.append(command)
                        print(f"{RED}FAILURE{RESET} - Running command: {command}")
                        self._log_command(log_file=FAIL_LOG_FILE, command=command, stdout=stdout, stderr=stderr)
                except asyncio.exceptions.TimeoutError:
                    self.timedout_commands.append(command)
                    print(f"{YELLOW}TIMEOUT{RESET} - Running command: {command}")
                    self._log_command(log_file=TIMEOUT_LOG_FILE, command=command)

    @staticmethod
    def _run_subprocess(zsh_command: str, timeout: int) -> tuple:
        # Running the command in a subprocess with a specified timeout
        try:
            proc = subprocess.run(zsh_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            return proc, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            raise FuturesTimeoutError() from None

    @staticmethod
    def _log_command(log_file: str, command: str, stdout: bytes = None, stderr: bytes = None) -> None:
        # Logging the command, its output, and errors to the specified log file
        with open(log_file, 'a') as f:
            f.write(f"COMMAND: {command}\n")
            if stdout is not None: f.write(f"└── STDOUT:\n{stdout.decode('utf-8', 'replace')}\n")
            if stderr is not None: f.write(f"└── STDERR:\n{stderr.decode('utf-8', 'replace')}\n")


def read_commands(file: str) -> list[str]:
    # Reading commands from the specified file
    with open(file, 'r') as f:
        return sorted([cmd.strip() for cmd in f.readlines()])


async def main():
    runner = CommandRunner(parallel_tasks=CONCURRENT_TASKS)
    commands = read_commands(COMMANDS_FILE)
    await runner.run(commands)

    # Displaying summary of the results and log locations
    if runner.failed_commands or runner.timedout_commands:
        if runner.failed_commands:
            print(f"{YELLOW}The following commands failed:{RESET}")
            for command in runner.failed_commands:
                print(f"    {command}")
        if runner.timedout_commands:
            print(f"{YELLOW}The following commands timed out:{RESET}")
            for command in runner.timedout_commands:
                print(f"    {command}")
        print(f"{YELLOW}Logs of failed commands are stored in{RESET} {FAIL_LOG_FILE}")
        print(f"{YELLOW}Logs of timedout commands are stored in{RESET} {TIMEOUT_LOG_FILE}")
        print(f"{YELLOW}Logs of success commands are stored in{RESET} {SUCCESS_LOG_FILE}")
        exit(1)
    else:
        print("All commands succeeded.")
        print(f"{YELLOW}Logs of success commands are stored in{RESET} {SUCCESS_LOG_FILE}")

# Running the main coroutine
asyncio.run(main())