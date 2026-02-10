"""
RetDec integration module for binary analysis.

Provides decompilation service integration for a single binary per MCP server session.
"""

from typing import Dict, Any, Optional
import os
import httpx
import datetime

from pwnomcp.logger import logger


class RetDecAnalyzer:
    """
    RetDec decompilation service analyzer for single binary analysis.

    Initializes at startup with BINARY_URL environment variable and
    stores the analysis result for subsequent MCP calls.
    """

    RETDEC_SERVICE_URL = "https://retdec.pwno.io"

    def __init__(self):
        """
        Initialize the RetDec analyzer.

        :param None:
        """
        self.binary_url: Optional[str] = os.environ.get("BINARY_URL")
        self.analysis_result: Optional[Dict[str, Any]] = None
        self._initialized = False

    async def initialize(self) -> Dict[str, Any]:
        """
        Initialize and analyze the binary from BINARY_URL environment variable.

        :returns: Analysis initialization result
        """
        if self._initialized:
            logger.info("RetDec analyzer already initialized")
            return self.analysis_result or {"status": "already_initialized"}

        self._initialized = True

        if not self.binary_url:
            logger.info(
                "No BINARY_URL environment variable found, skipping RetDec analysis"
            )
            self.analysis_result = {
                "status": "skipped",
                "message": "No BINARY_URL environment variable provided",
            }
            return self.analysis_result

        # Perform the analysis
        return await self._analyze_binary()

    async def _analyze_binary(self) -> Dict[str, Any]:
        """
        Analyze the binary using RetDec decompilation service.

        :returns: Analysis result dictionary
        """
        logger.info(f"Calling RetDec decompile service for binary: {self.binary_url}")

        try:
            async with httpx.AsyncClient(timeout=300.0) as client:
                response = await client.post(
                    f"{self.RETDEC_SERVICE_URL}/decompile",
                    json={"url": self.binary_url},
                )

                if response.status_code == 200:
                    decompiled_data = response.json()
                    self.analysis_result = {
                        "status": "success",
                        "decompiled": decompiled_data,
                        "binary_url": self.binary_url,
                        "analyzed_at": datetime.datetime.utcnow().isoformat(),
                    }
                    logger.info("RetDec decompilation completed successfully")
                else:
                    self.analysis_result = {
                        "status": "failed",
                        "error": f"Failed to decompile: HTTP {response.status_code}",
                        "details": response.text,
                        "binary_url": self.binary_url,
                        "analyzed_at": datetime.datetime.utcnow().isoformat(),
                    }
                    logger.error(f"RetDec decompilation failed: {response.status_code}")

        except httpx.TimeoutError:
            logger.error("RetDec service timeout")
            self.analysis_result = {
                "status": "failed",
                "error": "Decompilation timeout (300s)",
                "binary_url": self.binary_url,
                "analyzed_at": datetime.datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.error(f"RetDec service error: {e}", exc_info=True)
            self.analysis_result = {
                "status": "failed",
                "error": f"Decompilation failed: {str(e)}",
                "binary_url": self.binary_url,
                "analyzed_at": datetime.datetime.utcnow().isoformat(),
            }

        return self.analysis_result

    def get_decompiled_code(self) -> Optional[str]:
        """
        Get decompiled code if available.

        :returns: Decompiled C code or None if not available
        """
        if not self.analysis_result:
            return None

        if self.analysis_result.get("status") != "success":
            return None

        decompiled = self.analysis_result.get("decompiled", {})
        if decompiled.get("status") == "success":
            return decompiled.get("decompiled_code", "")

        return None

    def get_status(self) -> Dict[str, Any]:
        """
        Get the current analysis status.

        :returns: Status dictionary with analysis information
        """
        if not self.analysis_result:
            return {
                "status": "not_analyzed",
                "message": "No RetDec decompilation has been performed",
            }

        if self.analysis_result.get("status") == "skipped":
            return {
                "status": "skipped",
                "message": self.analysis_result.get("message", "Analysis was skipped"),
            }

        if self.analysis_result.get("status") == "failed":
            return {
                "status": "failed",
                "error": self.analysis_result.get("error"),
                "details": self.analysis_result.get("details"),
                "analyzed_at": self.analysis_result.get("analyzed_at"),
            }

        if self.analysis_result.get("status") == "success":
            decompiled = self.analysis_result.get("decompiled", {})
            return {
                "status": "success",
                "analyzed_at": self.analysis_result.get("analyzed_at"),
                "has_code": bool(decompiled.get("decompiled_code")),
                # "binary_url": self.analysis_result.get("binary_url")
            }

        return {"status": "unknown", "message": "Analysis status is unknown"}
