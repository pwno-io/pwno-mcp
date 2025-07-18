#!/usr/bin/env python3
"""
Run the PwnoMCP server
"""

import asyncio
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pwnomcp.server import main

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown requested...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)