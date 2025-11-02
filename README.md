# Linux System Call Table (Generated)

This repository hosts a comprehensive Linux system call table in Markdown format, generated dynamically for the x86_64 architecture. The table lists each syscall's number, name, brief description, and function prototype, providing a useful reference for developers, students, or system programmers.

## About This Repository

- The main focus is the **generated Markdown file** (`Linux_Syscall_Table.md`) containing the detailed Linux syscall information.
- This file serves as a ready-to-use, GitHub-friendly documentation resource.
- If you want to **generate or update this Markdown table on your own system**, a Python script (`linux_syscall_table.py`) is also provided.
  - The script extracts syscall data using system header files and man pages.
  - You can customize it according to your architecture or preferences.

## Usage

- Browse the Markdown file directly in this repository for quick syscall lookup.
- Or run the Python script locally to regenerate or update the table:

```
python3 linux_syscall_table.py > Linux_Syscall_Table.md
```

## Contributing

Contributions to improve the table, script, or documentation are welcome. Please open issues or submit pull requests.

