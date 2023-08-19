import os
import re
import sys

blue = "\033[1;34m"
magenta = "\033[1;35m"
clear = "\033[0m"

def is_whitelisted(check_function_name, function_content):
    """Check if the function content is whitelisted based on # CODE-CHECK-WHITELIST directive."""
    for line in function_content.split("\n"):
        if line.strip().startswith("# CODE-CHECK-WHITELIST="):
            _, arguments = line.strip().split("=")
            if check_function_name in arguments:
                return True
    return False

def get_functions_with_content(filename):
    """Extract functions starting with 'install_' and their content."""
    with open(filename, 'r') as file:
        content = file.read()

    pattern = r'function\s+(install_\w+)\(\)\s+({[^}]*\n})'
    return re.findall(pattern, content, re.DOTALL)

def contains_target_function(function_content, target_function):
    """Check if the function content contains the target function, not commented."""
    for line in function_content.split("\n"):
        stripped_line = line.strip()
        if target_function in stripped_line and not stripped_line.startswith("#"):
            return True
    return False

def main(check_function_name):
    error = False
    for root, _, files in os.walk("./sources/install/"):
        for file in files:
            if file.startswith("package_") and file.endswith(".sh"):
                file_path = os.path.join(root, file)
                for func_name, func_content in get_functions_with_content(file_path):
                    if not contains_target_function(func_content, check_function_name) and not is_whitelisted(check_function_name, func_content):
                        print(f"{magenta}File: {file_path}{clear}")
                        print(f"{blue}Function: {func_name}{clear}")
                        print(func_content)
                        error = True
    return error

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script_name.py <check_function_name>")
        sys.exit(1)
    if main(sys.argv[1]):
        exit(1)
