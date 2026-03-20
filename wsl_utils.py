import platform
import os
import subprocess

def is_running_on_wsl():
    return (
        platform.system().lower() == "linux"
        and os.path.exists('/proc/sys/fs/binfmt_misc/WSLInterop')
    )

def convert_windows_path_to_wsl(windows_path):
    if not (windows_path and ("\\" in windows_path or (len(windows_path) > 1 and windows_path[1] == ":"))):
            return windows_path
    try:
        result = subprocess.run(['wslpath', '-u', windows_path], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to convert windows path '{windows_path}': {e}")

