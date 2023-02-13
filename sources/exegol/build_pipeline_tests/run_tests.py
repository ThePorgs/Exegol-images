import subprocess
import threading
import tempfile

# The file containing the list of commands
commands_file = "/.exegol/build_pipeline_tests/all_commands.sorted.txt"

# The file to store the logs of failed commands
log_file = "/.exegol/build_pipeline_tests/failed_commands.log"

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
            output = subprocess.check_output(zsh_command, shell=True, stderr=subprocess.PIPE)
            print(f"\033[1;32mSUCCESS\033[0m - Running command: {command}")
        except subprocess.CalledProcessError as e:
            # If the command fails, store it in the list of failed commands
            failed_commands.append(command)
            print(f"\033[1;31mFAILURE\033[0m - Running command: {command}")

            # Write the output of the failed command to the log file
            with open(log_file, "a") as f:
                f.write(f"\033[1;34mFailed command: {command}\n\033[0m")
                f.write(f"\033[1;33mStandard output: {e.output.decode()}\n\033[0m")
                f.write(f"Standard error: {e.stderr.decode()}\n\033[0m")


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
    print("The following commands failed:")
    for command in failed_commands:
        print(command)
    print(f"Logs of failed commands are stored in {log_file}")
    exit(1)
else:
    print("All commands succeeded.")
    exit(0)
