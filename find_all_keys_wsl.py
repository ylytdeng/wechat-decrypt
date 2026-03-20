## This script is a simple wsl port of the existing windows script
## We can not access the memory of a wechat process running on windows from wsl
## So we simply call the windows version of python to find the keys
## Requires python to be installed on both wsl and windows with the relevant dependencies

import subprocess
import os
import ast
import json


BASEPATH = os.path.dirname(os.path.abspath(__file__))
# convert to a windows format:
try:
    WINDOWS_DIR = subprocess.check_output(["wslpath", "-w", BASEPATH], text=True).strip()
except subprocess.CalledProcessError as e:
    raise Exception(f"Error: Could not translate WSL path to Windows path: {e}")


def get_pids():
    result_flag = "#RESULT: "
    call_windows_script_command = f"""
import sys
sys.path.append({json.dumps(WINDOWS_DIR)})
from find_all_keys_windows import get_pids

res = get_pids()
print('{result_flag}' + str(res))
"""
    result = subprocess.run(["python.exe", "-c", call_windows_script_command], capture_output=True, text=True)
    
    if result.returncode != 0:
        raise Exception(f"Error while getting the pids on windows: {result.stderr}")
    try:
        output_lines = result.stdout.strip().split("\n")
        result_line = next((line for line in output_lines if line.startswith(result_flag)), None)
        if result_line is None:
            raise ValueError
        result_string = result_line[len(result_flag):].strip()
        return ast.literal_eval(result_string)
    except (SyntaxError, ValueError, IndexError) as e:
        raise Exception(f"Error while parsing windows output: {e}\nRaw output: {result.stdout}")
        

def main():
    windows_full_path = rf"{WINDOWS_DIR}\find_all_keys_windows.py"
    result = subprocess.run(["python.exe", windows_full_path])
    if result.returncode != 0:
        raise Exception("error during key extraction on windows")
