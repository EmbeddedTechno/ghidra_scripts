# -*- coding: utf-8 -*-
#@author 
#@category Custom
#@keybinding 
#@menupath Tools.AutomateFunctionIdentification_FromAggregatedSource
#@toolbar 

"""
This plugin automates the process of matching decompiled functions against candidate source functions
extracted from an aggregated source document.

For each function in the current program:
  1. The function is decompiled to obtain pseudo–C code.
  2. All string literals in the decompiled output are extracted.
  3. The aggregated source document is read and parsed to extract candidate source functions.
  4. Each candidate is scanned to see if it contains the decompiled function's string literals.
  5. If a match is found, the decompiled function is renamed and a plate comment is added with the source code.
  
Note: This is a proof–of–concept implementation using simple heuristics.
"""

import re, os, sys
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit
from ghidra.util import Msg

# Define an ensure_unicode helper. In Jython Python 2, strings read from files may be str;
# we want to ensure they are Unicode.
if sys.version_info[0] < 3:
    def ensure_unicode(text):
        if not isinstance(text, unicode):
            try:
                return text.decode("utf-8", "replace")
            except Exception as e:
                print("Error decoding text: {}".format(e))
                return text.decode("utf-8", "replace")
        return text
else:
    def ensure_unicode(text):
        return text

def normalize_for_comparison(text):
    """
    Normalizes text for robust substring matching.
    Converts text to Unicode (if not already), converts to lowercase,
    removes extra whitespace, and standardizes comma spacing.
    """
    try:
        text = ensure_unicode(text)
    except Exception as e:
        print("Error converting text to Unicode: {}. Using replacement.".format(e))
        try:
            text = unicode(text, "utf-8", errors="replace")
        except Exception as e2:
            print("Unable to decode text even with replacement: {}. Returning empty string.".format(e2))
            return ""
    text = text.lower()
    text = re.sub(r'\s*,\s*', ',', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

def decompile_function(func):
    """
    Uses Ghidra's decompiler interface to obtain a C-like representation of a function.
    """
    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    result = decomplib.decompileFunction(func, 60, TaskMonitor.DUMMY)
    if result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return None

def extract_strings(text):
    """
    Extracts all string literals from the given text.
    """
    return re.findall(r'"(.*?)"', text)

def extract_aggregated_functions(content):
    """
    Parses an aggregated source document (produced by the aggregator script) and extracts candidate functions.
    
    Each function block is expected to be delimited like:
      ------------------------------
      File: <file path>
      Function Name: <function name>
      ------------------------------
      <function code ...>
      ==============================
      
    Returns a list of tuples: (function_name, full_function_code)
    """
    funcs = []
    blocks = content.split("==============================")
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        lines = block.splitlines()
        if len(lines) >= 5 and lines[0].startswith('----------------'):
            header_line = lines[2]  # Expected "Function Name: <name>"
            if "Function Name:" in header_line:
                func_name = header_line.split("Function Name:",1)[-1].strip()
            else:
                func_name = ""
            # Function code begins after the header (skip header lines)
            func_code = "\n".join(lines[4:])
            funcs.append((func_name, func_code))
        else:
            funcs.append(("", block))
    return funcs

def rename_function_and_add_comment(func, new_name, source_code):
    """
    Renames the provided function in Ghidra to new_name and adds a plate comment with the source code.
    """
    try:
        old_name = func.getName()
        func.setName(new_name, SourceType.USER_DEFINED)
        listing = currentProgram.getListing()
        listing.setComment(func.getEntryPoint(), CodeUnit.PLATE_COMMENT, source_code)
        print("Renamed function at {} from '{}' to '{}' and added source as comment."
              .format(func.getEntryPoint(), old_name, new_name))
    except Exception as e:
        print("Error renaming function at {}: {}".format(func.getEntryPoint(), str(e)))

def main():
    # Prompt for the aggregated source document file.
    aggFileHandle = askFile("Select Aggregated Source File", "Open")
    if aggFileHandle is None:
        print("No aggregated source file selected. Exiting.")
        return
    agg_file = str(aggFileHandle.getAbsolutePath())
    print("Aggregated source file:", agg_file)
    
    try:
        with open(agg_file, "r") as f:
            agg_content = f.read()
    except Exception as e:
        print("Error reading aggregated source file: {}".format(e))
        return
    
    candidate_functions = extract_aggregated_functions(agg_content)
    print("Extracted {} candidate source functions from aggregated file.".format(len(candidate_functions)))
    
    # Process each function in the current program.
    funcManager = currentProgram.getFunctionManager()
    functions = funcManager.getFunctions(True)
    
    for func in functions:
        print("Processing function at {} ({})".format(func.getEntryPoint(), func.getName()))
        decompText = decompile_function(func)
        if not decompText:
            print("Could not decompile function at {}. Skipping.".format(func.getEntryPoint()))
            continue
        
        candidate_strings = extract_strings(decompText)
        if not candidate_strings:
            print("No string literals found in function at {}. Skipping.".format(func.getEntryPoint()))
            continue
        
        print("Function at {} contains candidate strings: {}".format(
            func.getEntryPoint(), candidate_strings))
        
        candidate_match = None
        for cand_func_name, cand_func_code in candidate_functions:
            normalized_source = normalize_for_comparison(cand_func_code)
            all_found = True
            for candidate in candidate_strings:
                try:
                    normalized_candidate = normalize_for_comparison(candidate)
                except Exception as e:
                    print("Error normalizing candidate string '{}': {}. Skipping candidate.".format(candidate, e))
                    all_found = False
                    break
                try:
                    if normalized_candidate not in normalized_source:
                        all_found = False
                        print("Candidate '{}' not found in aggregated function '{}'.".format(
                            normalized_candidate, cand_func_name))
                        break
                except UnicodeDecodeError as e:
                    print("UnicodeDecodeError during comparison for candidate '{}': {}. Skipping candidate.".format(
                          normalized_candidate, e))
                    all_found = False
                    break
            if all_found:
                candidate_match = (cand_func_name, cand_func_code)
                print("Match found: Aggregated source function '{}' used for function at {}.".format(
                    cand_func_name, func.getEntryPoint()))
                break
        
        if candidate_match:
            new_name, src_full_code = candidate_match
            rename_function_and_add_comment(func, new_name, src_full_code)
        else:
            print("No matching aggregated source function found for function at {}.".format(
                  func.getEntryPoint()))

if __name__ == "__main__":
    main()
