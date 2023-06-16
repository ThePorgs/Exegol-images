There are two folders which goal aims at customizing the queries for Bloodhound.
Exegol provides a default file, but the user may prefer a different customqueries.json

1/ replacement
A single customqueries.json file placed in the 'replacement' folder and having a size greater than zero, will overwrite Exegol's.

2/ merge
Any files ending with .json, placed in the 'merge' folder, with a size greater than zero will be merged with Exegol's.
This means that there could be several files, which can be named anything as long as they are ended with the extension .json

Remark:
'Replacement' has a priority over 'Merge'.
This means that as long as the 'replacement' condition is met, the outcome of 'merge' does not matter.
