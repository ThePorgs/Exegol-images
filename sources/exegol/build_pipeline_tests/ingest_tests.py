import json

MAX_JOBS = 250


# Dividing all_tests list into chunks of size n
def divide_tests(l, n):
    for i in range(0, len(l), n):
        yield str(l[i:i + n])


# Reading all test commands and converting to JSON structure
infile_path = "/.exegol/build_pipeline_tests/all_commands.sorted.txt"
with open(infile_path, 'r') as f:
    all_tests = f.read().splitlines()
    print(f"[+] Read all tests from {infile_path}")
    d = {'tests': list(divide_tests(all_tests, MAX_JOBS))}
    print(f"[+] Divided into chunks of size {MAX_JOBS}")
    json_tests = json.dumps(d)
    print("[+] Converted to JSON structure")


# Writing to tests.json
outfile_path = "/.exegol/build_pipeline_tests/tests.json"
with open(outfile_path, "w") as outfile:
    outfile.write(json_tests)
    print(f"[+] JSON structure written to file {outfile_path}")
