"""Versioned, salted scrypt with purpose-separated pepper and bounded concurrency."""

from __future__ import annotations

import hmac
import secrets
import threading

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class PasswordError(ValueError):
    """Password policy or stored verifier is invalid."""


class PasswordBusyError(RuntimeError):
    """Hash capacity is exhausted; fail without unbounded waiting or allocation."""


class PasswordHasher:
    _slots = threading.BoundedSemaphore(2)
    _prefix = "cf-scrypt-v1"

    def __init__(self, pepper: bytes) -> None:
        if len(pepper) < 32:
            raise ValueError("password pepper requires at least 32 bytes")
        self._pepper = hmac.digest(pepper, b"endpoint-password-v1", "sha256")

    @staticmethod
    def validate(password: str) -> None:
        if not 15 <= len(password) <= 128:
            raise PasswordError("Use a password or passphrase of 15-128 characters.")
        if len(set(password)) < 5 or password.casefold() in {
            "password123456789",
            "123456789012345",
            "qwertyuiop123456",
            "letmeinletmeinletmein",
        }:
            raise PasswordError("Choose a less predictable password or passphrase.")

    def _derive(self, password: str, salt: bytes) -> str:
        if not self._slots.acquire(blocking=False):
            raise PasswordBusyError("Please try again in a moment.")
        try:
            prehash = hmac.digest(self._pepper, password.encode("utf-8"), "sha256")
            return Scrypt(salt=salt, n=2**15, r=8, p=3, length=32).derive(prehash).hex()
        finally:
            self._slots.release()

    def hash(self, password: str) -> str:
        self.validate(password)
        salt = secrets.token_bytes(16)
        return f"{self._prefix}${salt.hex()}${self._derive(password, salt)}"

    def verify(self, password: str, encoded: str) -> bool:
        if len(password) > 128:
            return False
        try:
            prefix, salt_hex, expected = encoded.split("$")
            salt = bytes.fromhex(salt_hex)
            if prefix != self._prefix or len(salt) != 16 or len(bytes.fromhex(expected)) != 32:
                return False
        except ValueError:
            return False
        return hmac.compare_digest(self._derive(password, salt), expected)

    def dummy_verify(self, password: str) -> None:
        """Unknown accounts incur the same expensive primitive as known accounts."""
        self._derive(password[:128], bytes(16))
