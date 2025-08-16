"""RetDec integration module for binary analysis"""

from typing import Dict, Any, Optional
import os
import httpx
import datetime

from pwnomcp.logger import logger

RETDEC_SERVICE_URL = "https://retdec.pwno.io" 
# hardcoded, feel free to use it:) just not too much

retdec_results: Dict[str, Dict[str, Any]] = {}

async def analyze_binary_if_needed(binaro_id: str, binaro_url: str) -> None:
    if binaro_id in retdec_results or not binaro_url:
        return
    
    logger.info(f"Calling retdec decompile service for binaro {binaro_id}")
    
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(
                f"{RETDEC_SERVICE_URL}/decompile",
                json={"url": binaro_url}
            )
            
            retdec_results[binaro_id] = {
                "decompiled": response.json() if response.status_code == 200 else {
                    "error": f"Failed to decompile: {response.text}"
                },
                "binaro_url": binaro_url,
                "analyzed_at": datetime.datetime.utcnow().isoformat()
            }
            
            logger.info(f"RetDec decompilation completed for binaro {binaro_id}")
            
    except httpx.TimeoutError:
        logger.error(f"RetDec service timeout for binaro {binaro_id}")
        retdec_results[binaro_id] = {
            "decompiled": {"error": "Decompilation timeout"},
            "binaro_url": binaro_url,
            "analyzed_at": datetime.datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"RetDec service error for binaro {binaro_id}: {e}", exc_info=True)
        retdec_results[binaro_id] = {
            "decompiled": {"error": f"Decompilation failed: {str(e)}"},
            "binaro_url": binaro_url,
            "analyzed_at": datetime.datetime.utcnow().isoformat()
        }


def get_decompiled_code(binaro_id: str) -> Optional[str]:
    """Get decompiled code for a binaro if available"""
    if binaro_id not in retdec_results:
        return None
    
    result = retdec_results[binaro_id]
    decompiled = result.get("decompiled", {})
    
    if "error" in decompiled:
        return None
    
    if decompiled.get("status") == "success":
        return decompiled.get("decompiled_code", "")
    
    return None


def get_analysis_status(binaro_id: str) -> Dict[str, Any]:
    """Get the analysis status for a binaro"""
    if binaro_id not in retdec_results:
        return {
            "status": "not_analyzed",
            "message": "No RetDec decompilation available yet"
        }
    
    result = retdec_results[binaro_id]
    decompiled = result.get("decompiled", {})
    
    if "error" in decompiled:
        return {
            "status": "failed",
            "error": decompiled["error"],
            "analyzed_at": result.get("analyzed_at")
        }
    
    return {
        "status": "success",
        "analyzed_at": result.get("analyzed_at"),
        "has_code": bool(decompiled.get("decompiled_code"))
    } 