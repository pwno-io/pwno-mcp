#!/usr/bin/env python3
"""
Example WebSocket client for PwnoMCP live updates
"""

import asyncio
import json
import websockets
from datetime import datetime


class PwnoWebSocketClient:
    def __init__(self, url="ws://localhost:8765"):
        self.url = url
        self.running = True
        
    async def handle_message(self, data):
        """Handle incoming WebSocket message"""
        msg_type = data.get("type", "unknown")
        content = data.get("data", "")
        token = data.get("token")
        timestamp = data.get("timestamp")
        
        # Format timestamp
        if timestamp:
            dt = datetime.fromtimestamp(timestamp)
            time_str = dt.strftime("%H:%M:%S.%f")[:-3]
        else:
            time_str = "??:??:??"
            
        # Print based on type
        if msg_type == "state":
            print(f"[{time_str}] STATE: {content}")
            
        elif msg_type == "console":
            print(f"[{time_str}] CONSOLE: {content}")
            
        elif msg_type == "stdout":
            print(f"[{time_str}] STDOUT: {content}", end="")
            
        elif msg_type == "stderr":
            print(f"[{time_str}] STDERR: {content}")
            
        elif msg_type in ["registers", "stack", "code", "disasm"]:
            print(f"\n[{time_str}] === {msg_type.upper()} ===")
            print(content)
            
        elif msg_type == "heap":
            print(f"\n[{time_str}] HEAP INFO:")
            print(content)
            
        elif msg_type == "memory":
            print(f"\n[{time_str}] MEMORY:")
            print(content)
            
        else:
            print(f"[{time_str}] {msg_type.upper()}: {content}")
            
    async def connect(self):
        """Connect to WebSocket server and handle messages"""
        print(f"Connecting to {self.url}...")
        
        try:
            async with websockets.connect(self.url) as websocket:
                print("Connected to PwnoMCP WebSocket server")
                
                # Handle incoming messages
                async for message in websocket:
                    try:
                        data = json.loads(message)
                        await self.handle_message(data)
                    except json.JSONDecodeError:
                        print(f"Invalid JSON received: {message}")
                    except Exception as e:
                        print(f"Error handling message: {e}")
                        
        except websockets.exceptions.ConnectionRefused:
            print("Connection refused. Is the PwnoMCP server running?")
        except Exception as e:
            print(f"Connection error: {e}")
            
    async def run(self):
        """Run the client with reconnection logic"""
        while self.running:
            try:
                await self.connect()
            except KeyboardInterrupt:
                print("\nShutting down...")
                self.running = False
            except Exception as e:
                print(f"Unexpected error: {e}")
                
            if self.running:
                print("Reconnecting in 3 seconds...")
                await asyncio.sleep(3)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="PwnoMCP WebSocket Client")
    parser.add_argument(
        "--url",
        default="ws://localhost:8765",
        help="WebSocket server URL (default: ws://localhost:8765)"
    )
    
    args = parser.parse_args()
    
    client = PwnoWebSocketClient(args.url)
    
    try:
        asyncio.run(client.run())
    except KeyboardInterrupt:
        print("\nExiting...")


if __name__ == "__main__":
    main()