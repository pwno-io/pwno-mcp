"""
PwnoMCP main entry point
"""

import asyncio
import sys
from pwnomcp.server import main

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown requested...")
        sys.exit(0)