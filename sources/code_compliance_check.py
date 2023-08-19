import os
import re
import sys

blue = "\033[1;34m"
magenta = "\033[1;35m"
clear = "\033[0m"


def is_whitelisted(check_function_name, function_content):
    """Check if the function content is whitelisted based on # CODE-CHECK-WHITELIST directive."""
    for line in function_content.split("\n"):
        # Get the argument list from CODE-CHECK-WHITELIST
        if line.strip().startswith("# CODE-CHECK-WHITELIST="):
            _, arguments = line.strip().split("=")
            # Checking if the target checked function is in exclusion whitelist
            if check_function_name in arguments:
                return True
    return False


def get_functions_with_content(filename):
    """Extract functions starting with 'install_' and their content."""
    with open(filename, 'r') as file:
        content = file.read()
    # Regex to retrieve function name and content
    pattern = r'function\s+(install_\w+)\(\)\s+({[^}]*\n})'
    return re.findall(pattern, content, re.DOTALL)


def contains_target_function(function_content, target_function):
    """Check if the function content calls the target function (and that the call is not commented)"""
    for line in function_content.split("\n"):
        stripped_line = line.strip()
        if target_function in stripped_line and not stripped_line.startswith("#"):
            return True
    return False


def is_code_compliant(check_function_name):
    compliant = True
    # Browse all files in the installation folder
    for root, _, files in os.walk("./sources/install/"):
        for file in files:
            # Parse only files that have the package prefix and are sh files
            if file.startswith("package_") and file.endswith(".sh"):
                file_path = os.path.join(root, file)
                # Get function name and content
                for func_name, func_content in get_functions_with_content(file_path):
                    # Raising logs and noncompliance if target function is not in exclusion list for this function, and is not called in its content
                    if not contains_target_function(func_content, check_function_name) and not is_whitelisted(check_function_name, func_content):
                        print(f"{magenta}File: {file_path}{clear}")
                        print(f"{blue}Function: {func_name}{clear}")
                        print(func_content)
                        compliant = False
    return compliant

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 code_compliance_check.py <check_function_name>")
        sys.exit(1)
    if not is_code_compliant(sys.argv[1]):
        exit(1)
