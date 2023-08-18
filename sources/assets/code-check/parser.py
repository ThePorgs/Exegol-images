#!/usr/bin/env python3

import sys
import re

blue = "\033[1;34m"
magenta = "\033[1;35m"
clear = "\033[0m"

def non_compliance(file_dict, input_string):
    not_compliant = False
    for element in file_dict["functions"]:
        if not element.startswith("install_"):
            continue
        formatted_string = r"text: `({})`".format(element)
        function_name_match = re.search(formatted_string, input_string)
        if function_name_match:
            content = r'text: `({})`\n.*?text: `(.*?)`'.format(element)
            body_pattern = re.compile(content, re.DOTALL)
            body_match = body_pattern.search(input_string)
            if body_match:
                print(f"{magenta}File : {file_dict['filename']}{clear}")
                print(f"{blue}Function : {body_match.group(1)}{clear}")
                print(body_match.group(2), end='\n\n')
                not_compliant = True
    return(not_compliant)

def get_functions_name(input_string):
    lines = input_string.strip().split('\n')
    file_pattern = re.compile(r'^(?P<path>.*/)?(?P<filename>\w+\.sh)')
    name_pattern = re.compile(r'text: `(?P<name>[\w_]+)`')
    i = 0
    result = []
    while i < len(lines):
        line = lines[i]
        if file_pattern.match(line):
            current_file = {
                "filename": line,
                "functions": []
            }
            result.append(current_file)
            i += 1
            continue
        if name_pattern.search(line):
            current_file["functions"].append(name_pattern.search(line).group('name'))
            i += 1
            continue
        i += 1
    return result

if __name__ == "__main__":
    input_string = sys.stdin.read()
    files_and_functions = get_functions_name(input_string)
    compliant = 0
    for file_dict in files_and_functions:
        if non_compliance(file_dict, input_string):
            compliant = 1
    exit(compliant)
