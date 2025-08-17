import logging

from rich.logging import RichHandler

logger = logging.getLogger("")

handler = RichHandler(rich_tracebacks=True)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
