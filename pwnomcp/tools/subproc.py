"""
Subprocess execution tools for Pwno MCP

Provides tools for running system commands, particularly useful for:
- Compiling binaries with various flags (ASAN, debug symbols, etc.)
- Running helper scripts
- Managing background processes
"""

import logging
import subprocess
import shlex
from typing import Dict, Any, Optional, List
import psutil
import os

logger = logging.getLogger(__name__)


class SubprocessTools:
    """Tools for subprocess execution and management"""
    
    def __init__(self):
        """Initialize subprocess tools"""
        self.background_processes: Dict[int, subprocess.Popen] = {}
        
    def run_command(self, command: str, cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None, 
                   timeout: Optional[float] = 30.0) -> Dict[str, Any]:
        """
        Execute a command and wait for it to complete
        
        This is primarily intended for compilation commands like:
        - gcc -g -fsanitize=address program.c -o program
        - clang -O0 -g -fno-omit-frame-pointer vuln.c
        - make clean && make
        
        Args:
            command: Command to execute (will be shell-parsed)
            cwd: Working directory for the command
            env: Environment variables (merged with current env)
            timeout: Maximum execution time in seconds
            
        Returns:
            Dictionary with execution results
        """
        logger.info(f"Running command: {command}")
        
        try:
            # Parse command for safer execution
            cmd_parts = shlex.split(command)
            
            # Prepare environment
            cmd_env = os.environ.copy()
            if env:
                cmd_env.update(env)
                
            # Execute command
            result = subprocess.run(
                cmd_parts,
                cwd=cwd,
                env=cmd_env,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                "success": result.returncode == 0,
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "cwd": cwd or os.getcwd()
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "command": command,
                "error": f"Command timed out after {timeout} seconds",
                "cwd": cwd or os.getcwd()
            }
        except Exception as e:
            logger.error(f"Failed to run command: {e}")
            return {
                "success": False,
                "command": command,
                "error": str(e),
                "cwd": cwd or os.getcwd()
            }
            
    def spawn_process(self, command: str, cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Spawn a background process and return immediately
        
        Useful for starting long-running processes like:
        - Web servers for exploitation
        - Network listeners
        - Monitoring scripts
        
        Args:
            command: Command to execute
            cwd: Working directory for the command
            env: Environment variables
            
        Returns:
            Dictionary with process information including PID
        """
        logger.info(f"Spawning process: {command}")
        
        try:
            # Parse command
            cmd_parts = shlex.split(command)
            
            # Prepare environment
            cmd_env = os.environ.copy()
            if env:
                cmd_env.update(env)
                
            # Spawn process
            process = subprocess.Popen(
                cmd_parts,
                cwd=cwd,
                env=cmd_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Store process reference
            self.background_processes[process.pid] = process
            
            # Check if process started successfully
            # Give it a moment to potentially fail
            import time
            time.sleep(0.1)
            
            if process.poll() is not None:
                # Process already terminated
                stdout, stderr = process.communicate()
                return {
                    "success": False,
                    "command": command,
                    "error": "Process terminated immediately",
                    "returncode": process.returncode,
                    "stdout": stdout,
                    "stderr": stderr
                }
                
            return {
                "success": True,
                "command": command,
                "pid": process.pid,
                "cwd": cwd or os.getcwd(),
                "status": "running"
            }
            
        except Exception as e:
            logger.error(f"Failed to spawn process: {e}")
            return {
                "success": False,
                "command": command,
                "error": str(e)
            }
            
    def get_process_status(self, pid: int) -> Dict[str, Any]:
        """
        Get status of a spawned process
        
        Args:
            pid: Process ID to check
            
        Returns:
            Dictionary with process status
        """
        try:
            # Check if we're tracking this process
            if pid in self.background_processes:
                process = self.background_processes[pid]
                poll_result = process.poll()
                
                if poll_result is None:
                    # Still running
                    return {
                        "success": True,
                        "pid": pid,
                        "status": "running",
                        "cpu_percent": psutil.Process(pid).cpu_percent(),
                        "memory_info": psutil.Process(pid).memory_info()._asdict()
                    }
                else:
                    # Process finished
                    stdout, stderr = process.communicate()
                    del self.background_processes[pid]
                    
                    return {
                        "success": True,
                        "pid": pid,
                        "status": "terminated",
                        "returncode": poll_result,
                        "stdout": stdout,
                        "stderr": stderr
                    }
            else:
                # Try to check if process exists anyway
                if psutil.pid_exists(pid):
                    proc = psutil.Process(pid)
                    return {
                        "success": True,
                        "pid": pid,
                        "status": "running" if proc.is_running() else "unknown",
                        "name": proc.name(),
                        "cmdline": " ".join(proc.cmdline())
                    }
                else:
                    return {
                        "success": False,
                        "pid": pid,
                        "error": "Process not found"
                    }
                    
        except Exception as e:
            logger.error(f"Failed to get process status: {e}")
            return {
                "success": False,
                "pid": pid,
                "error": str(e)
            }
            
    def kill_process(self, pid: int, signal: int = 15) -> Dict[str, Any]:
        """
        Kill a process
        
        Args:
            pid: Process ID to kill
            signal: Signal to send (default: SIGTERM=15, use 9 for SIGKILL)
            
        Returns:
            Dictionary with kill result
        """
        try:
            if pid in self.background_processes:
                process = self.background_processes[pid]
                process.terminate() if signal == 15 else process.kill()
                process.wait(timeout=5)
                del self.background_processes[pid]
            else:
                os.kill(pid, signal)
                
            return {
                "success": True,
                "pid": pid,
                "signal": signal,
                "status": "killed"
            }
            
        except ProcessLookupError:
            return {
                "success": False,
                "pid": pid,
                "error": "Process not found"
            }
        except Exception as e:
            logger.error(f"Failed to kill process: {e}")
            return {
                "success": False,
                "pid": pid,
                "error": str(e)
            }
            
    def list_processes(self) -> Dict[str, Any]:
        """
        List all tracked background processes
        
        Returns:
            Dictionary with process list
        """
        processes = []
        
        for pid, process in list(self.background_processes.items()):
            poll_result = process.poll()
            if poll_result is None:
                # Still running
                try:
                    proc_info = psutil.Process(pid)
                    processes.append({
                        "pid": pid,
                        "status": "running",
                        "name": proc_info.name(),
                        "cmdline": " ".join(proc_info.cmdline()),
                        "cpu_percent": proc_info.cpu_percent(),
                        "memory_mb": proc_info.memory_info().rss / 1024 / 1024
                    })
                except:
                    processes.append({
                        "pid": pid,
                        "status": "running",
                        "error": "Could not get process info"
                    })
            else:
                # Process terminated, clean up
                del self.background_processes[pid]
                
        return {
            "success": True,
            "processes": processes,
            "count": len(processes)
        } 