import json
import platform

MAX_JOBS = 250

def runner_arch():
    raw_arch = platform.machine().lower()
    arch = raw_arch
    if arch == "x86_64" or arch == "x86-64" or arch == "amd64":
        arch = "amd64"
    elif arch == "aarch64" or "armv8" in arch:
        arch = "arm64"
    elif "arm" in arch:
        if platform.architecture()[0] == '64bit':
            arch = "arm64"
        else:
            raise (f"Host architecture seems to be 32-bit ARM ({arch}), which is not supported yet. "
                         f"If possible, please install a 64-bit operating system (Exegol supports ARM64).")
        """
        if "v5" in arch:
            arch = "arm/v5"
        elif "v6" in arch:
            arch = "arm/v6"
        elif "v7" in arch:
            arch = "arm/v7"
        elif "v8" in arch:
            arch = "arm64"
        """
    else:
        raise f"Unknown / unsupported architecture: {arch}."
    return arch

# Dividing all_tests list into chunks of size n
def divide_tests(l, n):
    for i in range(0, len(l), n):
        yield str(l[i:i + n])


# Reading all test commands and converting to JSON structure
infile_path = "/.exegol/build_pipeline_tests/all_commands.sorted.txt"
with open(infile_path, 'r') as f:
    all_tests = f.read().splitlines()
    print(f"[+] Read all tests from {infile_path}")
    print(f"[+] Divided into chunks of size {MAX_JOBS}")
    json_tests = json.dumps(list(divide_tests(all_tests, MAX_JOBS)))
    print("[+] Converted to JSON structure")


# Writing to tests.json
outfile_path = "/.exegol/build_pipeline_tests/tests.json"
with open(outfile_path, "w") as outfile:
    outfile.write(json_tests)
    print(f"[+] JSON structure written to file {outfile_path}")

