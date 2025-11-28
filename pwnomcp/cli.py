"""
Simple client bindings for talking to a running pwno-mcp instance.

Currently exposes:
- attach: call the local /attach HTTP API (default http://127.0.0.1:5501)
"""

from __future__ import annotations

import textwrap
from typing import Iterable, List, Optional

import requests

from pwnomcp.router.attach import AttachRequest, AttachResponse

DEFAULT_ATTACH_BASE_URL = "http://127.0.0.1:5501"


def _normalize_script_lines(script: str) -> List[str]:
    """
    Normalize a multi-line gdbscript string into a list of non-empty lines.
    """
    if not script:
        return []
    dedented = textwrap.dedent(script)
    return [line for line in dedented.splitlines() if line.strip()]


def attach(
    pid: int,
    gdbscript: Optional[Iterable[str]] = None,
    artifact_path: Optional[str] = None,
    base_url: str = DEFAULT_ATTACH_BASE_URL,
    timeout: float = 10.0,
) -> AttachResponse:
    """
    Attach to an existing process via the local pwno-mcp attach server.

    This is a thin client over the FastAPI /attach endpoint implemented in
    pwnomcp.router.attach. It uses the original AttachRequest/AttachResponse
    models to ensure compatibility.

    Args:
        pid: Target process ID to attach to.
        gdbscript: Optional iterable of commands executed before attaching.
        where: Optional path to the target binary (mapped to AttachRequest.where).
        script_pid: Optional PID of the driving script (for bookkeeping).
        base_url: Base URL of the attach server (default http://127.0.0.1:5501).
        timeout: HTTP request timeout in seconds.

    Returns:
        AttachResponse parsed from the server response.
    """

    payload = AttachRequest(
        pre=list(gdbscript) if gdbscript is not None else None,
        pid=pid,
        where=artifact_path,
        after=None,
        script_pid=None,
    )

    url = f"{base_url.rstrip('/')}/attach"
    response = requests.post(url, json=payload.model_dump(), timeout=timeout)
    response.raise_for_status()

    data = response.json()
    return AttachResponse.model_validate(data)


