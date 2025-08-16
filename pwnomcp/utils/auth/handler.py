from functools import wraps
from pathlib import Path

from pwnomcp.logger import logger

class Nonce:
    def __init__(self):
        self.nonce_file_path = "/app/.nonce"
        self._local_nonce = None
        self._load_local_nonce()
    
    def _load_local_nonce(self):
        try:
            nonce_file = Path(self.nonce_file_path)
            if nonce_file.exists() and nonce_file.is_file():
                with open(nonce_file, 'r') as f:
                    nonce_content = f.read().strip()
                    if nonce_content:
                        self._local_nonce = nonce_content
                        logger.info(f"Loaded nonce from {self.nonce_file_path}, authentication enabled")
                    else:
                        logger.warning(f"Nonce file {self.nonce_file_path} is empty, authentication disabled")
                        self._local_nonce = None
            else:
                logger.info(f"Nonce file {self.nonce_file_path} not found, authentication disabled")
                self._local_nonce = None
        except Exception as e:
            logger.error(f"Error loading nonce: {e}, authentication disabled")
            self._local_nonce = None
    
    def extract_bearer_token(self, authorization_header: str) -> str:
        if not authorization_header:
            return None
        
        if authorization_header.startswith("Bearer "):
            return authorization_header[7:].strip()
        
        return None

    def verify_nonce(self, client_nonce: str) -> bool:
        if not self._local_nonce:
            logger.info("No local nonce found, authorizing request")
            # this is a meet in the middle, we need to guarantee usability of services
            # while gaurantee security
            return True
        
        if client_nonce == self._local_nonce:
            return True
        
        return False
    
    def authenticate_request(self, headers: dict) -> bool:
        auth_header = headers.get("Authorization", "")
        client_nonce = self.extract_bearer_token(auth_header)
        if not client_nonce and self._local_nonce:
            logger.warning("No client nonce provided but local nonce exists")
            return False
        
        return self.verify_nonce(client_nonce)

    def require_auth(self, func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            
            if args and hasattr(args[0], 'headers'):
                request = args[0]
            elif 'request' in kwargs:
                request = kwargs['request']
            
            headers = {}
            if request:
                if hasattr(request, 'headers'):
                    headers = request.headers
                elif hasattr(request, 'scope'):
                    headers = dict(request.scope.get('headers', []))
            
            if not self.authenticate_request(headers):
                logger.warning("Authentication failed")
                return {
                    "error": "Authentication failed",
                    "message": "Invalid or missing nonce"
                }, 401
            
            return await func(*args, **kwargs)
        return wrapper