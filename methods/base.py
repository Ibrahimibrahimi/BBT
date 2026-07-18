"""
Base class for all encoding/encryption methods.

Every method module in this folder must define a class that inherits
from `BaseMethod` and implements `encode()`. The loader will pick it
up automatically — no manual registration needed.
"""

from abc import ABC, abstractmethod


class BaseMethod(ABC):
    # Short name shown in the results table (e.g. "Base64", "MD5", "ROT13")
    name: str = "Unnamed"

    # One-line description shown in --list or verbose mode
    description: str = ""

    # Category used for grouping/coloring in the UI (e.g. "Encoding", "Hash", "Cipher")
    category: str = "Other"

    @abstractmethod
    def encode(self, text: str) -> str:
        """
        Take the input string and return the encoded/encrypted/hashed result
        as a string. Must never raise for normal text input — catch internal
        errors and return a readable message instead if something truly can't
        be encoded (the loader will still display it, marked as failed).
        """
        raise NotImplementedError
