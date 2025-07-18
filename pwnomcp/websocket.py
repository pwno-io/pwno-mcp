"""
WebSocket server for live GDB output updates
"""

import asyncio
import json
import logging
from typing import Set, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import websockets
from websockets.server import WebSocketServerProtocol

logger = logging.getLogger(__name__)


class UpdateType(Enum):
    """Types of updates sent via WebSocket"""
    CONSOLE = "console"
    STDOUT = "stdout"
    STDERR = "stderr"
    CONTEXT = "context"
    STATE = "state"
    BREAKPOINT = "breakpoint"
    HEAP = "heap"
    REGISTERS = "registers"
    STACK = "stack"
    MEMORY = "memory"
    ERROR = "error"


@dataclass
class WSUpdate:
    """WebSocket update message"""
    type: UpdateType
    data: Any
    token: Optional[int] = None
    timestamp: Optional[float] = None
    
    def to_json(self) -> str:
        """Convert to JSON for transmission"""
        import time
        self.timestamp = time.time()
        return json.dumps({
            "type": self.type.value,
            "data": self.data,
            "token": self.token,
            "timestamp": self.timestamp
        })


class WebSocketManager:
    """Manages WebSocket connections and broadcasts updates"""
    
    def __init__(self):
        self.clients: Set[WebSocketServerProtocol] = set()
        self.server = None
        self.update_queue: asyncio.Queue = asyncio.Queue()
        self._running = False
        
    async def register(self, websocket: WebSocketServerProtocol):
        """Register a new WebSocket client"""
        self.clients.add(websocket)
        logger.info(f"Client connected. Total clients: {len(self.clients)}")
        
        # Send initial state
        await self._send_initial_state(websocket)
        
    async def unregister(self, websocket: WebSocketServerProtocol):
        """Unregister a WebSocket client"""
        self.clients.discard(websocket)
        logger.info(f"Client disconnected. Total clients: {len(self.clients)}")
        
    async def _send_initial_state(self, websocket: WebSocketServerProtocol):
        """Send initial state to newly connected client"""
        try:
            # Import here to avoid circular dependency
            from pwnomcp.core.gdb_controller import gdb_controller
            
            # Send current inferior state
            state_update = WSUpdate(
                type=UpdateType.STATE,
                data={
                    "inferior_state": gdb_controller.inferior_state.name,
                    "gdb_initialized": gdb_controller.controller is not None
                }
            )
            await websocket.send(state_update.to_json())
            
        except Exception as e:
            logger.error(f"Error sending initial state: {e}")
            
    async def broadcast(self, update: WSUpdate):
        """Broadcast update to all connected clients"""
        if not self.clients:
            return
            
        message = update.to_json()
        
        # Send to all connected clients
        disconnected = set()
        for client in self.clients:
            try:
                await client.send(message)
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(client)
            except Exception as e:
                logger.error(f"Error broadcasting to client: {e}")
                disconnected.add(client)
                
        # Clean up disconnected clients
        for client in disconnected:
            await self.unregister(client)
            
    async def queue_update(self, update: WSUpdate):
        """Queue an update for broadcasting"""
        await self.update_queue.put(update)
        
    async def _broadcast_worker(self):
        """Worker to process update queue"""
        while self._running:
            try:
                update = await asyncio.wait_for(
                    self.update_queue.get(), 
                    timeout=0.1
                )
                await self.broadcast(update)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in broadcast worker: {e}")
                
    async def handle_client(self, websocket: WebSocketServerProtocol, path):
        """Handle a WebSocket client connection"""
        await self.register(websocket)
        try:
            # Keep connection alive and handle any incoming messages
            async for message in websocket:
                try:
                    data = json.loads(message)
                    # Handle client commands if needed
                    await self._handle_client_message(websocket, data)
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON from client: {message}")
                except Exception as e:
                    logger.error(f"Error handling client message: {e}")
        finally:
            await self.unregister(websocket)
            
    async def _handle_client_message(self, websocket: WebSocketServerProtocol, data: Dict[str, Any]):
        """Handle messages from clients"""
        # For now, we don't expect messages from clients
        # This can be extended for client commands
        pass
        
    async def start(self, host: str = "localhost", port: int = 8765):
        """Start the WebSocket server"""
        self._running = True
        
        # Start broadcast worker
        asyncio.create_task(self._broadcast_worker())
        
        # Start WebSocket server
        self.server = await websockets.serve(
            self.handle_client,
            host,
            port
        )
        logger.info(f"WebSocket server started on ws://{host}:{port}")
        
    async def stop(self):
        """Stop the WebSocket server"""
        self._running = False
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            
        # Close all client connections
        for client in list(self.clients):
            await client.close()
            
        logger.info("WebSocket server stopped")


# Global WebSocket manager instance
ws_manager = WebSocketManager()