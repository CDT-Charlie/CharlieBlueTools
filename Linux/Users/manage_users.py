import subprocess
import re
import os
import sys

def run_orchestrator():
    try:
        result = subprocess.run(['./list_users.sh'], capture_output=True, text=True, check=True)
        audit_output = result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Failed to run list_users.sh: {e}")
        return
    except FileNotFoundError:
        print("Error: list_users.sh not found in current directory.")
        return
    user_pattern = re.compile(r'^(\S+)\s+(\d+)\s+(\S+)', re.MULTILINE)
    users = []
    for match in user_pattern.finditer(audit_output):
        username, uid_str, status = match.groups()
        users.append((re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])').sub('', username), int(uid_str), status))
    print(users)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] This script must be run as root (sudo).")
        sys.exit(1)
    run_orchestrator()