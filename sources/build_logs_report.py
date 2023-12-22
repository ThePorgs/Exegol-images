# 1. Download log archive from image build job
# 2. Extract a file that looks like 0_Final image build (amd64) Build image Build or pull imag.txt
# 3. python3 build_logs_report.py <logfile.txt>

# Options like -t or -o to change the order and size of the report

import re
import sys
import argparse
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table


# Function to convert seconds to minutes
def seconds_to_minutes(seconds):
    return seconds / 60


# Function to format time in a human-readable way
def format_time(tmstp):
    return tmstp.strftime("%Hh%M")


# Create Console
console = Console()


# Set up argument parser
parser = argparse.ArgumentParser(description="Parse installation times and display in a table.")
parser.add_argument("input_file", help="Path to the input file")
parser.add_argument("--time-unit", "t", choices=["minutes", "seconds"], default="minutes",
                    help="Display time in minutes or seconds (default: minutes)")
parser.add_argument("--order-by", "-o", choices=["short", "time", "input"], default="short",
                    help="Display order of the table (default: short)")

# Parse command-line arguments
args = parser.parse_args()

# Read input data from the file
try:
    with open(args.input_file, 'r') as file:
        input_lines = file.readlines()
except FileNotFoundError:
    console.print(f"Error: File '{args.input_file}' not found.", style="bold red")
    sys.exit(1)

# Create a list to store installation information progressively
installations = []

# Iterate through lines and populate the installations list
for line_number, line in enumerate(input_lines):
    if "apt package(s)" in line:
        continue

    match = re.search(r'\[EXEGOL] Installing (.+)', line)
    if match:
        name = match.group(1).strip()
        time_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)', line)
        if time_match:
            timestamp_str = time_match.group(1)
            timestamp = datetime.fromisoformat(timestamp_str[:-1] + '+00:00')
            installations.append({"name": name, "start_time": timestamp, "line_number": line_number})

# Calculate installation times based on start times
for i in range(len(installations) - 1):
    time_taken = (installations[i]["start_time"] - installations[i + 1]["start_time"]).total_seconds()
    installations[i]["time_taken"] = abs(time_taken)

# Create a list of tuples with tool name, start time, and time taken
installation_info = [(inst["name"], inst["start_time"], inst.get("time_taken", 0)) for inst in installations]

# Sort the installation_info based on the user's choice
if args.order_by == "time":
    installation_info.sort(key=lambda x: x[2], reverse=True)
elif args.order_by == "short":
    installation_info = [(name, start_time, time_taken) for name, start_time, time_taken in installation_info if
                         time_taken > 60]
    installation_info.sort(key=lambda x: x[2], reverse=True)

# Calculate and display the total time taken to install everything
total_time_taken = sum(inst["time_taken"] for inst in installations if "time_taken" in inst)
total_time_taken_minutes = seconds_to_minutes(abs(total_time_taken))

# Create a Rich Table
table = Table(show_header=True, header_style="bold magenta", show_footer=True, footer_style="bold yellow3")

# Add columns to the table with footers
table.add_column(header="Name", footer="Total", style="cyan", justify="left")
table.add_column(header="Time Started", style="green", justify="left")
table.add_column(header="Time Taken",
                 footer=f"{total_time_taken_minutes:.2f} min" if args.time_unit == "minutes" else f"{total_time_taken:.2f} sec",
                 style="yellow", justify="right")

# Add sorted installation_info to the table
for tool_name, start_time, time_taken in installation_info:
    if args.time_unit == "minutes":
        time_taken = seconds_to_minutes(time_taken)
    table.add_row(tool_name, format_time(start_time),
                  f"{time_taken:.2f} min" if args.time_unit == "minutes" else f"{time_taken:.2f} sec")

# Print the table
console.print(table)
