#!/usr/bin/python3

import json, os, sys

if len(sys.argv) != 2:
    print("Error: Please provide the path of the directory containing the user's customqueries to merge with the Exegol image one.")
    exit(1)

directory_in = sys.argv[1]

if not os.path.isdir(directory_in):
    print("Error: The provided argument is not a valid directory path.")
    exit(2)

customqueries_file = "/root/.config/bloodhound/customqueries.json"


# Open the file for reading
try:
    with open(customqueries_file, "r", encoding='utf-8') as file:
        content = file.read()
except Exception:
    print(f"Unable to read '{customqueries_file}'")
    exit(3)


# List the files from directory_in ending with .json
if os.path.exists(directory_in) and os.access(directory_in, os.R_OK):
    additional_queries_files = [os.path.join(directory_in, file) for file in os.listdir(directory_in) if file.endswith(".json")]
else:
    print(f"The directory '{directory_in}' does not exist or is not readable.")
    exit(4)


# Append additional queries
json_data = json.loads(content)
extended = False

for queries_file in additional_queries_files:
    try:
        if os.path.getsize(queries_file) > 0:
            with open(queries_file, "r") as file:
                additional_queries_dict = json.load(file)
                json_data["queries"].extend(additional_queries_dict["queries"])
                extended = True
    except Exception:
        print(f"Unable to read '{queries_file}'")
        exit(5)


# Save the modified content back to the file
if extended is True:
    try:
        with open(customqueries_file, "w", encoding='utf-8') as file:
            file.write(json.dumps(json_data, indent=4))
    except Exception:
        print(f"Unable to write '{customqueries_file}'")
        exit(6)
