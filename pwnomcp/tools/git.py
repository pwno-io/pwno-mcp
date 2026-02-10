"""
Git repository management tools for Pwno MCP

Provides tools for fetching specific versions of git repositories.
Useful for analyzing specific vulnerable versions of software or libraries.
"""

import logging
import os
import shutil
import tempfile
from typing import Dict, Any, Optional
import subprocess

logger = logging.getLogger(__name__)


class GitTools:
    """Tools for git repository operations"""

    def __init__(self):
        """
        Initialize git tools.

        Sets up a workspace directory for cloned repositories.
        """
        self.workspace_dir = os.path.join(tempfile.gettempdir(), "project")
        os.makedirs(self.workspace_dir, exist_ok=True)
        logger.info(f"Git workspace initialized at: {self.workspace_dir}")

    def fetch_repo(
        self,
        repo_url: str,
        version: Optional[str] = None,
        target_dir: Optional[str] = None,
        shallow: bool = True,
    ) -> Dict[str, Any]:
        """
        Fetch a specific version of a git repository.

        :param repo_url: Git repository URL (https or ssh)
        :param version: Specific version to checkout (branch/tag/commit hash). If None, uses default branch
        :param target_dir: Target directory name. If None, derives from repo URL
        :param shallow: Whether to perform shallow clone (faster for large repos)
        :returns: Dictionary with fetch results including path and status
        """
        try:
            # Extract repo name if target_dir not specified
            if not target_dir:
                repo_name = repo_url.rstrip("/").split("/")[-1]
                if repo_name.endswith(".git"):
                    repo_name = repo_name[:-4]
                target_dir = repo_name

            # Full path for the repository
            repo_path = os.path.join(self.workspace_dir, target_dir)

            # Check if repo already exists
            if os.path.exists(repo_path):
                logger.info(f"Repository already exists at {repo_path}, removing...")
                shutil.rmtree(repo_path)

            # Clone the repository
            clone_cmd = ["git", "clone"]
            if shallow and version:
                # For specific versions, we need full clone to checkout
                clone_cmd.extend(["--depth", "1"])

            clone_cmd.extend([repo_url, repo_path])

            logger.info(f"Cloning repository: {repo_url}")
            result = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout for large repos
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": "Clone failed",
                    "stderr": result.stderr,
                    "command": " ".join(clone_cmd),
                }

            # Checkout specific version if requested
            checkout_info = None
            if version:
                logger.info(f"Checking out version: {version}")

                # First, fetch the specific ref if needed
                fetch_result = subprocess.run(
                    ["git", "fetch", "origin", version],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                )

                # Try to checkout the version
                checkout_result = subprocess.run(
                    ["git", "checkout", version],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                )

                if checkout_result.returncode != 0:
                    # Try as a remote branch
                    checkout_result = subprocess.run(
                        ["git", "checkout", "-b", version, f"origin/{version}"],
                        cwd=repo_path,
                        capture_output=True,
                        text=True,
                    )

                if checkout_result.returncode != 0:
                    return {
                        "success": False,
                        "error": "Checkout failed",
                        "stderr": checkout_result.stderr,
                        "clone_success": True,
                        "path": repo_path,
                    }

                checkout_info = checkout_result.stdout.strip()

            # Get current commit info
            commit_result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True,
            )
            current_commit = (
                commit_result.stdout.strip()
                if commit_result.returncode == 0
                else "unknown"
            )

            # Get branch info
            branch_result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True,
            )
            current_branch = (
                branch_result.stdout.strip()
                if branch_result.returncode == 0
                else "unknown"
            )

            return {
                "success": True,
                "path": repo_path,
                "repo_url": repo_url,
                "version": version or "default",
                "current_commit": current_commit,
                "current_branch": current_branch,
                "checkout_info": checkout_info,
                "workspace": self.workspace_dir,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Operation timed out", "timeout": 300}
        except Exception as e:
            logger.error(f"Git fetch error: {str(e)}")
            return {"success": False, "error": str(e), "type": type(e).__name__}

    def cleanup_workspace(self) -> Dict[str, Any]:
        """
        Clean up the git workspace directory.

        :returns: Dictionary with cleanup status
        """
        try:
            if os.path.exists(self.workspace_dir):
                shutil.rmtree(self.workspace_dir)
                os.makedirs(self.workspace_dir, exist_ok=True)
                return {
                    "success": True,
                    "message": "Workspace cleaned",
                    "path": self.workspace_dir,
                }
            else:
                return {
                    "success": True,
                    "message": "Workspace already clean",
                    "path": self.workspace_dir,
                }
        except Exception as e:
            logger.error(f"Cleanup error: {str(e)}")
            return {"success": False, "error": str(e)}
