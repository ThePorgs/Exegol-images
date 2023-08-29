import subprocess
import threading
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
success_log_file = "/.exegol/build_pipeline_tests/success_commands.log"

# Read the commands from the file
with open(commands_file) as f:
    commands = f.readlines()

# Remove the newline characters from the commands
commands = [x.strip() for x in commands]

# Initialize the variable to store the failed commands
failed_commands = []


# Define a function to run a single command
def run_command(command):
    # Create a temporary file for the command
    with tempfile.NamedTemporaryFile(mode="w") as temp:
        # Write the command to the temporary file
        temp.write(command)
        temp.flush()

        try:
            # Try to run the command in a zsh context
            zsh_command = f"zsh -c 'autoload -Uz compinit; compinit; source ~/.zshrc; . {temp.name}'"
            output = subprocess.check_output(zsh_command, shell=True, stderr=subprocess.PIPE, timeout=120)
            print(f"{green}SUCCESS{clear} - Running command: {command}")

            # Write the output of the successful command to the log file
            with open(success_log_file, "a") as f:
                f.write(f"{blue}mCommand: {command}\n{clear}")
                f.write(f"{yellow}Standard output:\n")
                for line in output.decode().split("\n"):
                    f.write(f"    {line}\n")
                f.write(f"{clear}")
        except subprocess.TimeoutExpired as e:
            # If the command timeout, store it in the list of failed commands
            failed_commands.append(command)
            print(f"{red}TIMEOUT{clear} - Running command: {command}")
        except subprocess.CalledProcessError as e:
            # If the command fails, store it in the list of failed commands
            failed_commands.append(command)
            print(f"{red}FAILURE{clear} - Running command: {command}")

            # Write the output of the failed command to the log file
            with open(fail_log_file, "a") as f:
                f.write(f"{blue}mFailed command: {command}\n{clear}")
                if e.output:
                    f.write(f"{yellow}Standard output:\n")
                    for line in e.output.decode().split("\n"):
                        f.write(f"    {line}\n")
                    f.write(f"{clear}")
                f.write(f"{red}Standard error:\n")
                for line in e.stderr.decode().split("\n"):
                    f.write(f"    {line}\n")
                f.write(f"{clear}")


# Create a list of threads
threads = [threading.Thread(target=run_command, args=(command,)) for command in commands]

# Start the threads
for thread in threads:
    thread.start()

# Wait for the threads to finish
for thread in threads:
    thread.join()

# Check if any of the commands failed
if failed_commands:
    print(f"{yellow}The following commands failed:{clear}")
    for command in failed_commands:
        print(f"    {command}")
    print(f"{yellow}Logs of failed commands are stored in{clear} {fail_log_file}")
    print(f"{yellow}Logs of success commands are stored in{clear} {success_log_file}")
    exit(1)
else:
    print("All commands succeeded.")
    print(f"{yellow}Logs of success commands are stored in{clear} {success_log_file}")
    exit(0)
