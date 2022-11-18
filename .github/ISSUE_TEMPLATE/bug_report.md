---
name: Bug report [IMAGE]
about: Report a bug in Exegol IMAGE to help us improve the Exegol environment
title: ''
labels: bug
assignees: ''

---

<!-- 
Verification before publication:

- You are creating a feature request in the Exegol IMAGE repository (the exegol environment)! 
If your request concerns the exegol command specific to the Exegol WRAPPER, please open your issue on the https://github.com/ShutdownRepo/Exegol repository
- Check that there is not already a issue for the same problem
- Some problems are already well known and can be found in the documentation or on the Exegol Discord
-->

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Create a container with Exegol image tag '...' in version 'x.y.z' with parameters '...'
2. Run the command `...`
3. Error message

**Expected behavior**
A clear and concise description of what you expected to happen.

**Screenshots**
If applicable, add screenshots to help explain your problem.

**Context information (please complete the following information):**

 - OS: [e.g. iOS]

- Exegol version (in debug `-vvv` mode):
```
exegol version -vvv
```

- Container information (in advanced `-vv` mode):
```
exegol info -vv <container_name>
```

**Additional context**

Add your customization logs:
```
zcat /var/log/exegol/var/log/exegol/load_setups.log.gz || cat /var/log/exegol/load_setups.log
```

Add any other context about the problem here.

**Exception**
If applicable, copy paste your exception stack:
```
<stacktrace content>
```
