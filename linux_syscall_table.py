import subprocess
import re

# Adjust path as needed for your architecture
SYSCALL_HEADER = '/usr/include/x86_64-linux-gnu/asm/unistd_64.h'

def extract_syscalls():
    syscalls = []
    with open(SYSCALL_HEADER, 'r') as file:
        for line in file:
            match = re.match(r'#define __NR_([a-z0-9_]+)\s+(\d+)', line)
            if match:
                name, num = match.groups()
                syscalls.append((int(num), name))
    return sorted(syscalls)

def get_syscall_info(syscall):
    description = "Description not found"
    signature = "Signature not found"

    try:
        result = subprocess.run(['man', '2', syscall], capture_output=True, text=True, timeout=3)
        lines = result.stdout.splitlines()

        # Extract description from "NAME" section
        name_index = next((i for i, line in enumerate(lines) if line.strip() == "NAME"), None)
        if name_index is not None:
            for line in lines[name_index+1:]:
                line = line.strip()
                if line:
                    description = line.split(" - ", 1)[1].strip() if " - " in line else line
                    break

        # Extract function prototype from "SYNOPSIS" section
        synopsis_index = next((i for i, line in enumerate(lines) if line.strip() == "SYNOPSIS"), None)
        if synopsis_index is not None:
            for line in lines[synopsis_index+1:]:
                if line.strip().startswith('#') or not line.strip():
                    continue
                signature = line.strip()
                break

    except Exception:
        pass

    return description, signature

def main():
    syscalls = extract_syscalls()
    print("| Syscall Number | Syscall Name | Brief Description | Function Prototype |")
    print("|----------------|--------------|-------------------|--------------------|")
    for num, name in syscalls:
        desc, sig = get_syscall_info(name)
        desc = desc.replace('|', '\\|')
        sig = sig.replace('|', '\\|')
        print(f"| {num} | {name} | {desc} | `{sig}` |")

if __name__ == "__main__":
    main()

