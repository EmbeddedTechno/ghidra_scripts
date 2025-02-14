# ghidra_scripts
Reverse engineering helper scripts for ghidra
FunctionFinder and sourcescrapper are meant to be used together. 

SourceScrapper: Parses all files in a given directory (source code, libraries, etc), extracts any function found within those files, then aggregates them into a single .txt file.

FunctionFinder: Takes the each decompiled function from ghidra, if the function contains string(s) it searches for a matching string in the aggregated file produced by SourceScrapper.
A matching string in a source function often means that is the source code for that particular decompiled function. If it finds a match it will then rename the function in ghidra to 
match the source function and then adds the source function as boilerplate/comment to the decompiled function for reference. 

Installation: Add them via ghidra script manager (or drop them in your ghidra_scripts folder), and run them from ghidra after doing initial analysis.

Disclaimer: Obviously these scripts are not magic, and string comparison isnt a foolproof tactic. They are meant to assist in reversing, not do it for you. As well, DO NOT try to run this
on an entire source code repository at once. While it wont necessarily fail, its better to break up the work into smaller chunks, depending on your system hardware.
