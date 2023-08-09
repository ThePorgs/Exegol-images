#!/bin/python3
import re
from jinja2 import Template
import sys

if __name__ == "__main__":
    with open("Dockerfile.j2", "r") as file:
        template = file.read()

    template = Template(template)

    for type in sys.argv[1:]:
        contex = {}
        found = True
        file = f"{type}.dockerfile"
        if type == "osint":
            contex["osint"] = True
        elif type == "web":
            contex["web"] = True
        elif type == "ad":
            contex["ad"] = True
        elif type == "light":
            contex["light"] = True
        elif type == "full":
            contex["full"] = True
            file = "Dockerfile"
        else:
            print(f"{type} not found")
            found = False

        if found:
            with open(file, "w") as f:
                f.write(re.sub(r"\n{3,}", "\n\n", template.render(contex)))
