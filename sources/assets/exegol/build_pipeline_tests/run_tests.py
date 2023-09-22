import asyncio
import tempfile

red = "\033[1;31m"
green = "\033[1;32m"
yellow = "\033[33m"
blue = "\033[1;34m"
clear = "\033[0m"

# The file containing the list of commands
commands_file = "/.exegol/build_pipeline_tests/all_commands.sorted.txt"

# The file to store the logs of commands
fail_log_file = "/.exegol/build_pipeline_tests/failed_commands.log"
timeout_log_file = "/.exegol/build_pipeline_tests/timedout_commands.log"
success_log_file = "/.exegol/build_pipeline_tests/success_commands.log"

# Read the commands from the file
with open(commands_file) as f:
    commands = f.readlines()

# Remove the newline characters from the commands
commands = [x.strip() for x in commands]

# Initialize the variable to store the failed/timedout commands
failed_commands = []
timedout_commands = []

# Define a function to run a single command
async def run_command(command):
    # Create a temporary file for the command
    with tempfile.NamedTemporaryFile(mode="w") as temp:
        # Write the command to the temporary file
        temp.write(command)
        temp.flush()
        try:
            # Try to run the command in a zsh context
            zsh_command = f"zsh -c 'autoload -Uz compinit; compinit; source ~/.zshrc; . {temp.name}'"
            proc = await asyncio.create_subprocess_shell(
                cmd=zsh_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=20)
            # check if the command was successful
            if proc.returncode == 0:
                print(f"{green}SUCCESS{clear} - Running command: {command}")
                # Write the output of the successful command to the log file
                with open(success_log_file, "a") as f:
                    f.write(f"{blue}mCommand: {command}\n{clear}")
                    f.write(f"{yellow}Standard output:\n")
                    for line in stdout.decode().split("\n"):
                        f.write(f"    {line}\n")
                    f.write(f"{clear}")
            else:
                # If the command fails, store it in the list of failed commands
                failed_commands.append(command)
                print(f"{red}FAILURE{clear} - Running command: {command}")
                # Write the output of the failed command to the log file
                with open(fail_log_file, "a") as f:
                    f.write(f"{blue}Failed command: {command}\n{clear}")
                    if stderr:
                        f.write(f"{yellow}Standard output:\n")
                        for line in stderr.decode().split("\n"):
                            f.write(f"    {line}\n")
                        f.write(f"{clear}")
                    f.write(f"{red}Standard error:\n")
                    for line in stderr.decode().split("\n"):
                        f.write(f"    {line}\n")
                    f.write(f"{clear}")
        except asyncio.TimeoutError as e:
            # If the command timeout, store it in the list of failed commands
            timedout_commands.append(command)
            print(f"{yellow}TIMEOUT{clear} - Running command: {command}")
            # Add the timed out command to the log file
            with open(timeout_log_file, "a") as f:
                f.write(f"{blue}Timed out command: {command}\n{clear}")


async def main():
    # Read the commands and create a list of coroutine objects
    coros = [run_command(command) for command in commands]
    # Run the coroutines concurrently
    await asyncio.gather(*coros)


# Run the event loop
asyncio.run(main())

# Check if any of the commands failed
if failed_commands:
    print(f"{yellow}The following commands failed:{clear}")
    for command in failed_commands:
        print(f"    {command}")
    print(f"{yellow}The following commands timedout:{clear}")
    for command in timedout_commands:
        print(f"    {command}")
    print(f"{yellow}Logs of failed commands are stored in{clear} {fail_log_file}")
    print(f"{yellow}Logs of timedout commands are stored in{clear} {timeout_log_file}")
    print(f"{yellow}Logs of success commands are stored in{clear} {success_log_file}")
    exit(1)
else:
    print("All commands succeeded.")
    print(f"{yellow}Logs of success commands are stored in{clear} {success_log_file}")
    exit(0)
