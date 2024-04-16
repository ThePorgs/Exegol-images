import os
import re
import sys
import datetime

BLUE = "\033[1;34m"
MAGENTA = "\033[1;35m"
CLEAR = "\033[0m"

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
    return re.findall(r'function\s+(install_\S+)\(\)\s+({[^}]*\n})', content, re.DOTALL)

def contains_target_function(function_content, target_function):
    """Check if the function content calls the target function (and that the call is not commented)"""
    return any(target_function in line.strip() and not line.strip().startswith("#")
               for line in function_content.split("\n"))

def is_code_compliant(check_type, check_function_name=None):
    """Checks the compliance of installation scripts based on the requested check type."""
    compliant = True
    today = datetime.date.today()
    # Walks through all files in the specified installation directory
    for root, _, files in os.walk("./sources/install/"):
        for file in files:
            if file.startswith("package_") and file.endswith(".sh"):
                file_path = os.path.join(root, file)
                # Extracts functions and their content
                for func_name, func_content in get_functions_with_content(file_path):
                    if check_type == "temp-fix":
                        # Looks for a temporary fix expiration date within the function content
                        date_found = re.search(r'temp_fix_limit="(\d{4}-\d{2}-\d{2})"', func_content)
                        if date_found and datetime.datetime.strptime(date_found.group(1), '%Y-%m-%d').date() < today:
                            print(f"{MAGENTA}File: {file_path}{CLEAR}")
                            print(f"{BLUE}Function: {func_name}{CLEAR}")
                            print(func_content)
                            compliant = False
                    elif check_type == "compliance":
                        # Checks if the target function is not called and is not whitelisted
                        if not contains_target_function(func_content, check_function_name) and not is_whitelisted(check_function_name, func_content):
                            print(f"{MAGENTA}File: {file_path}{CLEAR}")
                            print(f"{BLUE}Function: {func_name}{CLEAR}")
                            print(func_content)
                            compliant = False
    return compliant

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 code_compliance_check.py <check_function_name|temp-fix>")
        sys.exit(1)

    # Determines the type of check based on the passed argument
    check_type = "temp-fix" if sys.argv[1] == "temp-fix" else "compliance"
    check_function_name = None if sys.argv[1] == "temp-fix" else sys.argv[1]

    # Calls the checking function and exits with error if non-compliant
    if not is_code_compliant(check_type, check_function_name):
        sys.exit(1)