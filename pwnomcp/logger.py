import os
import logging

logger = logging.getLogger("")

prod_env = os.getenv("PROD", False)

if prod_env:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    handler.setFormatter(formatter)
else:
    try:
        from rich.logging import RichHandler
        handler = RichHandler(rich_tracebacks=True)
    except Exception:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
        handler.setFormatter(formatter)

logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
