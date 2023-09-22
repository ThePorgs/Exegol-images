import asyncio
import tempfile
import subprocess
from concurrent.futures import TimeoutError as FuturesTimeoutError

COMMANDS_FILE = "/.exegol/build_pipeline_tests/all_commands.sorted.txt"
FAIL_LOG_FILE = "/.exegol/build_pipeline_tests/failed_commands.log"
TIMEOUT_LOG_FILE = "/.exegol/build_pipeline_tests/timedout_commands.log"
SUCCESS_LOG_FILE = "/.exegol/build_pipeline_tests/success_commands.log"

RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[33m"
BLUE = "\033[1;34m"
RESET = "\033[0m"

COMMAND_TIMEOUT = 20
CONCURRENT_TASKS = 5

class CommandRunner:
    def __init__(self, parallel_tasks: int = 20):
        self.sem = asyncio.Semaphore(parallel_tasks)
        self.failed_commands = []
        self.timedout_commands = []

    async def run(self, commands: list[str]) -> None:
        await asyncio.gather(*(self._run_command(command) for command in commands))

    async def _run_command(self, command: str) -> None:
        async with self.sem:
            with tempfile.NamedTemporaryFile(mode='w') as temp:
                temp.write(command)
                temp.flush()
                zsh_command = f"zsh -c 'autoload -Uz compinit; compinit; source ~/.zshrc; . {temp.name}'"
                loop = asyncio.get_running_loop()
                try:
                    proc, stdout, stderr = await loop.run_in_executor(None, self._run_subprocess, zsh_command, COMMAND_TIMEOUT)
                    if proc.returncode == 0:
                        print(f"{GREEN}SUCCESS{RESET} - Running command: {command}")
                        # Write the output of the successful command to the log file
                        self._log_command(log_file=SUCCESS_LOG_FILE, command=command, stdout=stdout, stderr=stderr)
                    else:
                        # If the command fails, store it in the list of failed commands
                        self.failed_commands.append(command)
                        print(f"{RED}FAILURE{RESET} - Running command: {command}")
                        self._log_command(log_file=FAIL_LOG_FILE, command=command, stdout=stdout, stderr=stderr)
                except asyncio.exceptions.TimeoutError:
                    # If the command timeout, store it in the list of failed commands
                    self.timedout_commands.append(command)
                    print(f"{YELLOW}TIMEOUT{RESET} - Running command: {command}")
                    self._log_command(log_file=TIMEOUT_LOG_FILE, command=command)

    @staticmethod
    def _run_subprocess(zsh_command: str, timeout: int) -> tuple:
        try:
            proc = subprocess.run(zsh_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            return proc, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            raise FuturesTimeoutError() from None

    @staticmethod
    def _log_command(log_file: str, command: str, stdout: bytes = None, stderr: bytes = None) -> None:
        with open(log_file, 'a') as f:
            f.write(f"COMMAND: {command}\n")
            if stdout is not None: f.write(f"\tSTDOUT:\n{stdout.decode('utf-8', 'replace')}\n")
            if stderr is not None: f.write(f"\tSTDERR:\n{stderr.decode('utf-8', 'replace')}\n")


def read_commands(file: str) -> list[str]:
    with open(file, 'r') as f:
        return [cmd.strip() for cmd in f.readlines()]


async def main():
    runner = CommandRunner(parallel_tasks=CONCURRENT_TASKS)
    commands = read_commands(COMMANDS_FILE)
    await runner.run(commands)

    if runner.failed_commands:
        print(f"{YELLOW}The following commands failed:{RESET}")
        for command in runner.failed_commands:
            print(f"    {command}")
    if runner.timedout_commands:
        print(f"{YELLOW}The following commands timedout:{RESET}")
        for command in runner.timedout_commands:
            print(f"    {command}")
        print(f"{YELLOW}Logs of failed commands are stored in{RESET} {FAIL_LOG_FILE}")
        print(f"{YELLOW}Logs of timedout commands are stored in{RESET} {TIMEOUT_LOG_FILE}")
        print(f"{YELLOW}Logs of success commands are stored in{RESET} {SUCCESS_LOG_FILE}")
        exit(1)
    else:
        print("All commands succeeded.")
        print(f"{YELLOW}Logs of success commands are stored in{RESET} {SUCCESS_LOG_FILE}")

asyncio.run(main())