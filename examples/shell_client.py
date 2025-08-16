#!/usr/bin/env python3
"""
Minimal example of command execution on pwno-mcp server.
"""

import requests


def execute_command(command: str, server_url: str = "http://localhost:5500"):
    """
    Execute a shell command on the pwno-mcp server.
    
    Args:
        command: Shell command to execute
        server_url: URL of the pwno-mcp server
    
    Returns:
        Command output or error message
    """
    try:
        response = requests.post(
            f"{server_url}/execute-shell",
            json={"command": command}
        )
        
        if response.status_code == 200:
            result = response.json()
            if result['success']:
                return result.get('stdout', '') + result.get('stderr', '')
            else:
                return f"Error: {result.get('error', 'Command failed')}"
        else:
            return f"HTTP Error {response.status_code}"
    
    except Exception as e:
        return f"Connection error: {e}"


# Example usage
if __name__ == "__main__":
    # Execute simple commands
    print(execute_command("pwd"))
    print(execute_command("ls -la"))
    print(execute_command("echo 'Hello from pwno-mcp!'"))
    
    # Compile and run a C program
    execute_command("echo '#include <stdio.h>\nint main() { printf(\"Hello C!\\n\"); return 0; }' > hello.c")
    execute_command("gcc -o hello hello.c")
    print(execute_command("./hello"))



