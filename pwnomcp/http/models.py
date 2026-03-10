from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AttachRequest(BaseModel):
    """Request body for /attach."""

    pre: Optional[List[str]] = Field(default=None)
    pid: int
    after: Optional[List[str]] = Field(default=None)
    where: Optional[str] = Field(default=None)
    session_id: str


class AttachResponse(BaseModel):
    """Response body for /attach."""

    successful: bool
    attach: Optional[Dict[str, Any]] = None
    result: Dict[str, Any]
