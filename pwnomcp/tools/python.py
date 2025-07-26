"""
Python execution tools for Pwno MCP

Provides tools for running Python scripts with a shared virtual environment
preconfigured with common security research packages.
"""

import logging
import os
import subprocess
import tempfile
import json
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class PythonTools:
    """Tools for Python script execution with a shared preconfigured venv"""
    
    # Common packages for security research
    DEFAULT_PACKAGES = [
        "requests",
        "numpy",
        "ipython",
        "hexdump",
    ]
    
    def __init__(self):
        """
        Initialize Python tools with a single shared venv.
        """
        self.workspace_dir = os.path.join(tempfile.gettempdir(), "pwno_python_workspace")
        os.makedirs(self.workspace_dir, exist_ok=True)
        self.venv_path = os.path.join(self.workspace_dir, "shared_venv")
        logger.info(f"Python workspace initialized at: {self.workspace_dir}")
        
        # Initialize the shared venv
        self._initialize_venv()
        
    def _initialize_venv(self):
        """
        Initialize the shared venv and install default packages.
        """
        if not os.path.exists(self.venv_path):
            logger.info("Creating shared Python environment...")
            
            # Create venv using UV
            cmd = ["uv", "venv", self.venv_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("Installing default packages...")
                # Install default packages
                install_cmd = ["uv", "pip", "install", "--python", self.venv_path] + self.DEFAULT_PACKAGES
                install_result = subprocess.run(install_cmd, capture_output=True, text=True)
                
                if install_result.returncode == 0:
                    logger.info("Default packages installed successfully")
                else:
                    logger.warning(f"Some packages failed to install: {install_result.stderr}")
            else:
                logger.error(f"Failed to create venv: {result.stderr}")
        else:
            logger.info("Using existing shared Python environment")
        
    def execute_script(self, 
                      script_path: str,
                      args: Optional[List[str]] = None,
                      cwd: Optional[str] = None,
                      timeout: float = 300.0) -> Dict[str, Any]:
        """
        Execute a Python script in the shared venv.
        
        :param script_path: Path to the Python script to execute
        :param args: Arguments to pass to the script
        :param cwd: Working directory for script execution
        :param timeout: Execution timeout in seconds
        :returns: Execution results with stdout, stderr, and status
        """
        try:
            # Build command
            python_exe = os.path.join(self.venv_path, "bin", "python")
            cmd = [python_exe, script_path]
            if args:
                cmd.extend(args)
                
            logger.info(f"Executing Python script: {script_path}")
            
            # Execute script
            result = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                "success": result.returncode == 0,
                "script": script_path,
                "venv_path": self.venv_path,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": " ".join(cmd),
                "cwd": cwd or os.getcwd()
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "script": script_path,
                "error": f"Script execution timed out after {timeout} seconds"
            }
        except Exception as e:
            logger.error(f"Failed to execute script: {e}")
            return {
                "success": False,
                "script": script_path,
                "error": str(e),
                "type": type(e).__name__
            }
    
    def execute_code(self,
                    code: str,
                    cwd: Optional[str] = None,
                    timeout: float = 300.0) -> Dict[str, Any]:
        """
        Execute Python code directly.
        
        :param code: Python code to execute
        :param cwd: Working directory for execution
        :param timeout: Execution timeout in seconds
        :returns: Execution results
        """
        try:
            # Create temporary script file
            fd, script_path = tempfile.mkstemp(suffix=".py", prefix="pwno_script_")
            with os.fdopen(fd, 'w') as f:
                f.write(code)
                
            # Execute using execute_script
            result = self.execute_script(
                script_path,
                cwd=cwd,
                timeout=timeout
            )
            
            # Clean up temp file
            os.unlink(script_path)
            
            result["code_preview"] = code[:200] + "..." if len(code) > 200 else code
            return result
            
        except Exception as e:
            logger.error(f"Failed to execute code: {e}")
            return {
                "success": False,
                "error": str(e),
                "type": type(e).__name__
            }
    
    def install_packages(self,
                        packages: List[str],
                        upgrade: bool = False) -> Dict[str, Any]:
        """
        Install additional Python packages using UV.
        
        :param packages: List of packages to install
        :param upgrade: Whether to upgrade existing packages
        :returns: Installation results
        """
        try:
            # Build UV pip install command
            cmd = ["uv", "pip", "install", "--python", self.venv_path]
            if upgrade:
                cmd.append("--upgrade")
            cmd.extend(packages)
            
            logger.info(f"Installing packages: {packages}")
            
            # Run installation
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "packages": packages,
                    "venv_path": self.venv_path,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
            else:
                return {
                    "success": False,
                    "packages": packages,
                    "error": "Installation failed",
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode
                }
                
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Installation timed out",
                "packages": packages
            }
        except Exception as e:
            logger.error(f"Failed to install packages: {e}")
            return {
                "success": False,
                "error": str(e),
                "type": type(e).__name__,
                "packages": packages
            }
    
    def get_installed_packages(self) -> Dict[str, Any]:
        """
        Get list of installed packages in the shared venv.
        
        :returns: List of installed packages
        """
        try:
            cmd = ["uv", "pip", "list", "--python", self.venv_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "packages": result.stdout,
                    "venv_path": self.venv_path
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to list packages",
                    "stderr": result.stderr
                }
                
        except Exception as e:
            logger.error(f"Failed to list packages: {e}")
            return {
                "success": False,
                "error": str(e),
                "type": type(e).__name__
            } 