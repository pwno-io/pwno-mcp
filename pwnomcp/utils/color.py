import re
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

T = TypeVar("T")


def strip_ansi_codes(text: str) -> str:
    """Strip ANSI escape codes from text"""
    ansi_escape = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", text)


def strip_color(func: Callable[..., str | dict | Any]) -> Callable[..., str | dict | Any]:
    """
    Decorator that strips ANSI color codes from function results.

    Works recursively on:
    - String results
    - Dict values (recursively)
    - List items

    :param func: Function to decorate
    :return: Wrapped function that strips color codes from results
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        return _strip_color_recursive(result)

    return wrapper


def _strip_color_recursive(data: Any) -> Any:
    """Recursively strip ANSI codes from data structures"""
    if isinstance(data, str):
        return strip_ansi_codes(data)
    elif isinstance(data, dict):
        return {k: _strip_color_recursive(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_strip_color_recursive(item) for item in data]
    elif isinstance(data, tuple):
        return tuple(_strip_color_recursive(item) for item in data)
    else:
        return data
