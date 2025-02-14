# -*- coding: utf-8 -*-
#@author 
#@category Custom
#@keybinding 
#@menupath Tools.AggregateSourceFunctions
#@toolbar 

"""
This script recursively gathers all files from a user-specified source directory,
extracts all function definitions from every file (using a simple heuristic), and 
writes them out to a single output file. Each function is delimited by a header and footer.
"""

import os
import re

def extract_source_functions(content):
    """
    Naïvely extracts C-like function definitions from the given source content.
    Returns a list of tuples: (function_name, full_function_code).

    It uses a regex to detect a typical function signature followed by an opening brace,
    then uses brace counting to capture the entire function body.
    """
    funcs = []
    pattern = re.compile(
        r'([a-zA-Z_][\w\s\*\(\),]*\s+([a-zA-Z_][\w]*)\s*\([^;]*\))\s*\{',
        re.MULTILINE
    )
    for match in pattern.finditer(content):
        start = match.start()
        func_name = match.group(2)
        # Find the opening brace, starting at the end of the match.
        brace_pos = content.find('{', match.end()-1)
        if brace_pos == -1:
            continue
        brace_count = 1
        i = brace_pos + 1
        # Count matching braces to determine function boundaries.
        while i < len(content) and brace_count > 0:
            if content[i] == '{':
                brace_count += 1
            elif content[i] == '}':
                brace_count -= 1
            i += 1
        func_code = content[start:i]
        funcs.append((func_name, func_code))
    return funcs

def get_source_files(source_dir):
    """
    Recursively gathers every file under the given directory (including those
    reached via symbolic links) and returns a list of file paths.
    """
    file_list = []
    for root, dirs, files in os.walk(source_dir, followlinks=True):
        for file in files:
            file_path = os.path.join(root, file)
            file_list.append(file_path)
    return file_list

def aggregate_functions(source_dir, output_file):
    """
    Iterates through every source file in source_dir,
    extracts functions from each file, and writes the aggregated functions
    to the output_file with a header and footer for each.
    """
    source_files = get_source_files(source_dir)
    all_functions = []
    for src_file in source_files:
        try:
            with open(src_file, "r") as f:
                content = f.read()
        except Exception as e:
            print("Error reading file {}: {}".format(src_file, e))
            continue

        funcs = extract_source_functions(content)
        for func_name, func_code in funcs:
            header = (
                "------------------------------\n"
                "File: {}\n"
                "Function Name: {}\n"
                "------------------------------\n"
            ).format(src_file, func_name)
            footer = "\n==============================\n"
            all_functions.append(header + func_code + footer)
    
    try:
        with open(output_file, "w") as outf:
            outf.write("\n".join(all_functions))
        print("Aggregated {} functions from {} source files into '{}'".format(
                len(all_functions), len(source_files), output_file))
    except Exception as e:
        print("Error writing to output file {}: {}".format(output_file, e))

def main():
    # Prompt the user to select the source repository directory.
    sourceDirHandle = askDirectory("Select Source Repository Directory", "Choose")
    if sourceDirHandle is None:
        print("No source directory selected. Exiting.")
        return
    source_dir = str(sourceDirHandle.getAbsolutePath())
    print("Source directory:", source_dir)

    # Prompt the user to select an output file for aggregated functions.
    outputFileHandle = askFile("Select Output File for Aggregated Functions", "Save")
    if outputFileHandle is None:
        print("No output file selected. Exiting.")
        return
    output_file = str(outputFileHandle.getAbsolutePath())
    print("Output file:", output_file)
    
    aggregate_functions(source_dir, output_file)

if __name__ == "__main__":
    main()